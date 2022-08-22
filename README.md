# s3aliases

Aliases for S3-compatible datastores. A weekend project.

## Purpose

S3 implements its copy operation on data, rather than metadata. This means that
if you want to have the same object appear in 1000 places in an S3 bucket, you
must pay to store that object 1000x. For some use-cases (e.g. scale-out reads)
this is useful, but for many others, we'd prefer to implement "copy" as a
metadata operation, so that the same underlying data appears in a bucket
multiple times.

## Implementation

(So far this project has gotten one weekend of work. It isn't anywhere near to
achiving its aspirations.)

The aim is to retain two of S3's best features as much as possible:
 * serverless deployment
 * boundless scalability

Primary data is stored in an S3 bucket. Metadata is stored in DynamoDB. A
second S3 bucket is used as a cache for list operations: it turns out that it's
easier to implement the list operation by piggybacking atop S3's existing list
operation than it is to build atop DynamoDB. 

## TODO

* Wrap all of the functionality up into a lambda function. Avoid processing
  blob bodies by calling the lambda function as an S3 signer.
* Replicate uploaded blob metadata within the inodes table (it's immutable).
  Use S3 data events to trigger the lambda to do the replication.
* Pulumi for infrastructure-as-code + repeatability
* Verification of correctness under concurrency
* Fault recovery (what happens if we fail to perform an update to the S3 metadata bucket)
* Multipart upload API
* Directory aliases (currently we only support aliases to blobs)

## Infrastructure

* Data bucket
* Metadata bucket, with versioning enabled and 1-day expiration of non-current objects
* 3 DynamoDB tables
  * dentries: maps filenames to randomized inode numbers
  * inodes: maps inode numbers to reference counts
  * inode_owners: reverse mapping of inodes to dentries
* An IAM role with the ability 
