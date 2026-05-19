package aws

import corestore "github.com/vercel-labs/emulate/internal/core/store"

type Store struct {
	S3Buckets   *corestore.Collection
	S3Objects   *corestore.Collection
	SQSQueues   *corestore.Collection
	SQSMessages *corestore.Collection
	IAMUsers    *corestore.Collection
	IAMRoles    *corestore.Collection
}

func NewStore(runtimeStore *corestore.Store) Store {
	return Store{
		S3Buckets:   runtimeStore.MustCollection("aws.s3_buckets", "bucket_name"),
		S3Objects:   runtimeStore.MustCollection("aws.s3_objects", "key", "bucket_name"),
		SQSQueues:   runtimeStore.MustCollection("aws.sqs_queues", "queue_name", "queue_url"),
		SQSMessages: runtimeStore.MustCollection("aws.sqs_messages", "message_id", "queue_name"),
		IAMUsers:    runtimeStore.MustCollection("aws.iam_users", "user_name", "user_id"),
		IAMRoles:    runtimeStore.MustCollection("aws.iam_roles", "role_name", "role_id"),
	}
}
