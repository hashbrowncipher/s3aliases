import logging
from os import urandom
from base64 import urlsafe_b64encode
from pprint import pprint
from itertools import islice

from boto3 import client
from boto3 import resource
from boto3.dynamodb.types import TypeSerializer
from boto3.dynamodb.types import TypeDeserializer
from boto3.dynamodb.conditions import Attr, Key
import boto3
import traceback

from botocore.history import get_global_history_recorder


class HistoryHandler:
    @staticmethod
    def emit(event_type, payload, source):
        if event_type != "HTTP_REQUEST":
            return

        pprint(payload)
        print()


recorder = get_global_history_recorder()
recorder.enable()
recorder.add_handler(HistoryHandler)


serialize = TypeSerializer().serialize
deserialize = TypeDeserializer().deserialize


def make_ddb(**kwargs):
    return {k: serialize(v) for (k, v) in kwargs.items()}


def unmake_ddb(item):
    return {k: deserialize(v) for (k, v) in item.items()}


def make_eav(**kwargs):
    return {(":" + k): serialize(v) for (k, v) in kwargs.items()}


def make_op(op, **kwargs):
    return {op: dict(**kwargs)}


DYNAMO = client("dynamodb")
Table = resource("dynamodb").Table
BUCKET = resource("s3").Bucket("aliasestest")
DENTRIES_BUCKET = resource("s3").Bucket("aliasesdentries")
DYNAMO_DENTRIES = Table("s3aliases_dentries")
DYNAMO_INODE_OWNERS = Table("s3aliases_inode_owners")
DYNAMO_INODES = Table("s3aliases_inodes")


def make_inode():
    return urandom(24)


def format_inode(s):
    return urlsafe_b64encode(s).decode()


def delete_object(key):
    existing = DYNAMO_DENTRIES.get_item(Key=dict(key=key)).get("Item")
    if not existing:
        return

    if "inode" in existing:
        actions, deleted_inode = _actions_to_update_existing_dentry(
            key, existing["inode"], None
        )
        DYNAMO.transact_write_items(TransactItems=actions)
        if deleted_inode:
            _cleanup_inode(deleted_inode)

    _purge_dentry_cache(key, existing)


def _actions_to_update_existing_dentry(key, current_inode, new_inode):
    deleted_inode = None
    ret = []

    inode_metadata = DYNAMO_INODES.get_item(Key=dict(inode=current_inode))["Item"]
    refcount = int(inode_metadata["refcount"])

    if new_inode is None:
        ret.append(
            make_op(
                "Update",
                TableName="s3aliases_dentries",
                Key=make_ddb(key=key),
                UpdateExpression="REMOVE inode",
                ConditionExpression="inode = :old_inode",
                ExpressionAttributeValues=make_eav(
                    old_inode=current_inode,
                ),
            )
        )
    else:
        ret.append(
            make_op(
                "Update",
                TableName="s3aliases_dentries",
                Key=make_ddb(key=key),
                UpdateExpression="SET inode = :new_inode",
                ConditionExpression="inode = :old_inode",
                ExpressionAttributeValues=make_eav(
                    old_inode=current_inode,
                    new_inode=new_inode,
                ),
            )
        )

    ret.append(
        make_op(
            "Delete",
            TableName="s3aliases_inode_owners",
            Key=make_ddb(inode=current_inode, dentry=key),
        )
    )

    if refcount == 1:
        deleted_inode = current_inode
        ret.append(
            make_op(
                "Update",
                TableName="s3aliases_inodes",
                Key=make_ddb(inode=current_inode),
                ExpressionAttributeValues=make_eav(
                    deletable="t",
                    old_refcount=1,
                ),
                UpdateExpression="REMOVE refcount SET deletable = :deletable",
                ConditionExpression="refcount = :old_refcount",
            )
        )
    else:
        ret.append(
            make_op(
                "Update",
                TableName="s3aliases_inodes",
                Key=make_ddb(inode=current_inode),
                ExpressionAttributeValues=make_eav(
                    refcount=refcount - 1,
                    old_refcount=refcount,
                ),
                UpdateExpression="SET refcount = :refcount",
                ConditionExpression="refcount = :old_refcount",
            )
        )

    return ret, deleted_inode


def _purge_dentry_cache(key, existing):
    version_id = existing["cache_versionid"]
    DENTRIES_BUCKET.Object(key).Version(version_id).delete()

    DYNAMO_DENTRIES.delete_item(
        Key=dict(key=key),
        ExpressionAttributeValues={":version": version_id},
        ConditionExpression="attribute_not_exists(inode) AND cache_versionid = :version",
    )


def _populate_dentry_cache(key, existing):
    if existing and "cache_versionid" in existing:
        return

    cache_entry = DENTRIES_BUCKET.Object(key)

    # Yes, the put is necessary.
    # Without it, we could store the version_id of a cache_entry that some
    # other request is about to delete.
    cache_entry.put()
    cache_entry.load()
    print(cache_entry.version_id)

    DYNAMO_DENTRIES.update_item(
        Key=dict(key=key),
        UpdateExpression="SET cache_versionid = :version",
        ExpressionAttributeValues={":version": cache_entry.version_id},
        # Not 100% confident in this condition
        ConditionExpression="attribute_not_exists(cache_versionid)",
    )


def _put_inode_for_key(key, inode, *, copy: bool):
    deleted_inode = None
    existing = DYNAMO_DENTRIES.get_item(Key=dict(key=key)).get("Item")
    actions = []

    if existing and "inode" in existing:
        existing_inode = existing["inode"]
        if existing_inode == inode:
            # Nothing to do!
            return

        sub_actions, deleted_inode = _actions_to_update_existing_dentry(
            key, existing_inode, inode
        )
        actions.extend(sub_actions)
    else:
        if existing:
            _purge_dentry_cache(key, existing)

        actions.append(
            make_op(
                "Put",
                TableName="s3aliases_dentries",
                Item=make_ddb(key=key, inode=inode),
                ExpressionAttributeNames={"#key": "key"},
                ConditionExpression="attribute_not_exists(#key)",
            )
        )

    if copy:
        # The inode already exists; increment its refcount
        actions.append(
            make_op(
                "Update",
                TableName="s3aliases_inodes",
                Key=make_ddb(inode=inode),
                ExpressionAttributeValues=make_eav(delta=1),
                UpdateExpression="SET refcount = refcount + :delta",
            )
        )
    else:
        # inode doesn't exist; create a row for it
        actions.append(
            make_op(
                "Put",
                TableName="s3aliases_inodes",
                Item=make_ddb(inode=inode, refcount=1),
                ConditionExpression="attribute_not_exists(inode)",
            )
        )

    # record the existence of a new dentry owning this inode
    actions.append(
        make_op(
            "Put",
            TableName="s3aliases_inode_owners",
            Item=make_ddb(inode=inode, dentry=key),
        )
    )

    # Raises a TransactionCanceledException when the conditions fail, or in
    # other circumstances.
    if actions:
        DYNAMO.transact_write_items(TransactItems=actions)

    if deleted_inode:
        _cleanup_inode(deleted_inode)

    if inode is not None:
        _populate_dentry_cache(key, existing)


def _cleanup_inode(inode):
    s3_inode(bytes(inode)).delete()
    DYNAMO_INODES.delete_item(Key=dict(inode=inode))


def put_object(key):
    inode = make_inode()
    _put_inode_for_key(key, inode, copy=False)
    s3_inode(inode).put(Body=urandom(1024))


def s3_inode(inode):
    return BUCKET.Object(format_inode(inode))


def _get_inode_for_key(key):
    resp = DYNAMO_DENTRIES.get_item(Key=dict(key=key))
    try:
        item = resp["Item"]
    except KeyError:
        return None

    # TODO: handle when item["inode"] is None
    return bytes(item["inode"])


def get_object(key):
    inode = _get_inode_for_key(key)
    print(s3_inode(inode).get())


def copy_object(key, source_key):
    inode = _get_inode_for_key(source_key)
    _put_inode_for_key(key, inode, copy=True)


def chunks(xs, n):
    xs = iter(xs)
    while True:
        if chunk := list(islice(xs, n)):
            yield chunk
        else:
            break


def _fetch_dentries_chunk(chunk):
    resp = DYNAMO.batch_get_item(
        RequestItems=dict(
            s3aliases_dentries=dict(Keys=[make_ddb(key=key) for key in chunk])
        )
    )

    return dict(
        (
            (item["key"], bytes(item["inode"]))
            for item in map(unmake_ddb, resp["Responses"]["s3aliases_dentries"])
        )
    )


def list_objects():
    s3_keys = map(lambda o: o.key, DENTRIES_BUCKET.objects.all())
    for chunk in chunks(s3_keys, 100):
        lut = _fetch_dentries_chunk(chunk)
        for key in chunk:
            data_object = s3_inode(lut[key])
            data_object.load()
            print(f"Key: {key}")
            print(f"Size: {data_object.content_length}")
            print(f"ETag: {data_object.e_tag}")
            print(f"Last Modified: {data_object.last_modified}")


def main():
    client("sts").get_caller_identity()
    ops = dict(
        get=get_object,
        put=put_object,
        delete=delete_object,
        copy=copy_object,
        list=list_objects,
    )
    while True:
        try:
            cmd = input("> ")
        except EOFError:
            break

        if not cmd:
            break

        try:
            op_name, *args = cmd.split()
            op = ops[op_name]
            op(*args)
        except:
            traceback.print_exc()


if __name__ == "__main__":
    raise SystemExit(main())
