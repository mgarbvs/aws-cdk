import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as core from 'aws-cdk-lib/core';
import type { Construct } from 'constructs';
import * as s3tables from '../../lib';

/**
 * Test cases:
 *
 * | props.encryption | props.encryptionKey | tableEncryption (expected)      | encryptionKey (expected)      |
 * |------------------|---------------------|---------------------------------|-------------------------------|
 * | KMS              | undefined           | aws:kms                         | new key (allow maintenance SP)|
 * | KMS              | k                   | aws:kms                         | k                             |
 * | S3_MANAGED       | undefined           | AES256                          | undefined                     |
 * | undefined        | k                   | aws:kms                         | k                             |
 */

class KMSAutoKeyTest extends core.Stack {
  constructor(scope: Construct, id: string, props?: core.StackProps) {
    super(scope, id, props);
    const tableBucket = new s3tables.TableBucket(this, 'TableBucket', {
      tableBucketName: 'integ-table-enc-kms-auto',
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
    const namespace = new s3tables.Namespace(this, 'Namespace', {
      namespaceName: 'test_namespace',
      tableBucket,
    });
    new s3tables.Table(this, 'Table', {
      tableName: 'test_table',
      namespace,
      openTableFormat: s3tables.OpenTableFormat.ICEBERG,
      encryption: s3tables.TableBucketEncryption.KMS,
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
  }
}

class KMSUserKeyTest extends core.Stack {
  constructor(scope: Construct, id: string, props?: core.StackProps) {
    super(scope, id, props);
    const key = new kms.Key(this, 'Key', {
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
    const tableBucket = new s3tables.TableBucket(this, 'TableBucket', {
      tableBucketName: 'integ-table-enc-kms-user',
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
    const namespace = new s3tables.Namespace(this, 'Namespace', {
      namespaceName: 'test_namespace',
      tableBucket,
    });
    new s3tables.Table(this, 'Table', {
      tableName: 'test_table',
      namespace,
      openTableFormat: s3tables.OpenTableFormat.ICEBERG,
      encryption: s3tables.TableBucketEncryption.KMS,
      encryptionKey: key,
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
  }
}

class S3ManagedTest extends core.Stack {
  constructor(scope: Construct, id: string, props?: core.StackProps) {
    super(scope, id, props);
    const tableBucket = new s3tables.TableBucket(this, 'TableBucket', {
      tableBucketName: 'integ-table-enc-s3-managed',
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
    const namespace = new s3tables.Namespace(this, 'Namespace', {
      namespaceName: 'test_namespace',
      tableBucket,
    });
    new s3tables.Table(this, 'Table', {
      tableName: 'test_table',
      namespace,
      openTableFormat: s3tables.OpenTableFormat.ICEBERG,
      encryption: s3tables.TableBucketEncryption.S3_MANAGED,
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
  }
}

class OnlyEncryptionKeyTest extends core.Stack {
  constructor(scope: Construct, id: string, props?: core.StackProps) {
    super(scope, id, props);
    const key = new kms.Key(this, 'Key', {
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
    const tableBucket = new s3tables.TableBucket(this, 'TableBucket', {
      tableBucketName: 'integ-table-enc-key-only',
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
    const namespace = new s3tables.Namespace(this, 'Namespace', {
      namespaceName: 'test_namespace',
      tableBucket,
    });
    new s3tables.Table(this, 'Table', {
      tableName: 'test_table',
      namespace,
      openTableFormat: s3tables.OpenTableFormat.ICEBERG,
      encryptionKey: key,
      removalPolicy: core.RemovalPolicy.DESTROY,
    });
  }
}

const app = new core.App();

const testCases = [
  new KMSAutoKeyTest(app, 'TableEncKMSAutoKeyTest', {}),
  new KMSUserKeyTest(app, 'TableEncKMSUserKeyTest', {}),
  new S3ManagedTest(app, 'TableEncS3ManagedTest', {}),
  new OnlyEncryptionKeyTest(app, 'TableEncOnlyKeyTest', {}),
];

new IntegTest(app, 'TableEncryptionIntegTest', { testCases });

app.synth();
