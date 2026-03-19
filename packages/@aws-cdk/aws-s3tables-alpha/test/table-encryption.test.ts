import { Match, Template } from 'aws-cdk-lib/assertions';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as core from 'aws-cdk-lib/core';
import * as s3tables from '../lib';
import { singletonOrArr as stringIfSingle } from './test-utils';
import * as perms from '../lib/permissions';

const TABLE_CFN_RESOURCE = 'AWS::S3Tables::Table';
const TABLE_POLICY_CFN_RESOURCE = 'AWS::S3Tables::TablePolicy';
const KMS_KEY_CFN_RESOURCE = 'AWS::KMS::Key';
const EXISTING_ROLE_ARN = 'arn:aws:iam::123456789012:role/existing-role';
const TABLE_BUCKET_NAME = 'test-table-bucket';

/* Allow quotes in the object keys used for CloudFormation template assertions */
/* eslint-disable @stylistic/quote-props */

describe('Table with encryption', () => {
  let stack: core.Stack;
  let namespace: s3tables.Namespace;
  let table: s3tables.Table;
  let role: iam.Role;
  let importedRole: iam.IRole;
  let user: iam.User;
  let userKey: kms.IKey;

  beforeEach(() => {
    stack = new core.Stack();
    const tableBucket = new s3tables.TableBucket(stack, 'TestTableBucket', {
      tableBucketName: TABLE_BUCKET_NAME,
    });
    namespace = new s3tables.Namespace(stack, 'TestNamespace', {
      namespaceName: 'test_namespace',
      tableBucket,
    });
    role = new iam.Role(stack, 'TestRole', { assumedBy: new iam.ServicePrincipal('sample') });
    user = new iam.User(stack, 'TestUser');
    importedRole = iam.Role.fromRoleArn(stack, 'ImportedRole', EXISTING_ROLE_ARN);
  });

  /**
   * Templatizes grant tests across different test suites.
   *
   * @param withKMS whether to test for KMS policies
   * @param keyName physical name of the KMS key to verify against
   */
  const grantTests = ({ withKMS, keyName }: { withKMS: boolean; keyName?: string }) => {
    enum GrantType { READ = 'read', WRITE = 'write', READ_WRITE = 'read & write' }

    const grantPermissions = (t: s3tables.Table, grantType: GrantType, principal: iam.IGrantable) => {
      switch (grantType) {
        case GrantType.READ:
          t.grantRead(principal);
          return;
        case GrantType.WRITE:
          t.grantWrite(principal);
          return;
        case GrantType.READ_WRITE:
          t.grantReadWrite(principal);
      }
    };

    interface TestCase {
      category: string;
      grantType: GrantType;
      actions: string | string[];
      keyActions: string | string[];
    }

    const testCases: TestCase[] = [
      {
        category: 'grantRead',
        grantType: GrantType.READ,
        actions: stringIfSingle(perms.TABLE_READ_ACCESS),
        keyActions: stringIfSingle(perms.KEY_READ_ACCESS),
      },
      {
        category: 'grantWrite',
        grantType: GrantType.WRITE,
        actions: stringIfSingle(perms.TABLE_WRITE_ACCESS),
        keyActions: stringIfSingle(perms.KEY_WRITE_ACCESS),
      },
      {
        category: 'grantReadWrite',
        grantType: GrantType.READ_WRITE,
        actions: stringIfSingle(perms.TABLE_READ_WRITE_ACCESS),
        keyActions: stringIfSingle(perms.KEY_READ_WRITE_ACCESS),
      },
    ];

    testCases.forEach(({ category, grantType, actions, keyActions }) => {
      describe(category, () => {
        const tableArnRef = { 'Fn::GetAtt': [Match.stringLikeRegexp('TestTable.*'), 'TableARN'] };

        const expectedStatements: any = [{
          'Action': actions,
          'Effect': 'Allow',
          'Resource': tableArnRef,
        }];
        if (withKMS) {
          expectedStatements.push({
            'Action': keyActions,
            'Effect': 'Allow',
            'Resource': { 'Fn::GetAtt': [keyName, 'Arn'] },
          });
        }

        it(`creates ${grantType} IAM policies for a role ${withKMS && 'and key'}`, () => {
          grantPermissions(table, grantType, role);
          Template.fromStack(stack).hasResourceProperties('AWS::IAM::Policy', {
            'PolicyDocument': {
              'Statement': expectedStatements,
              'Version': '2012-10-17',
            },
          });
          Template.fromStack(stack).resourceCountIs(TABLE_POLICY_CFN_RESOURCE, 0);
        });

        it(`creates ${grantType} IAM policies for a user ${withKMS && 'and key'}`, () => {
          grantPermissions(table, grantType, user);
          Template.fromStack(stack).hasResourceProperties('AWS::IAM::Policy', {
            'PolicyDocument': {
              'Statement': expectedStatements,
              'Version': '2012-10-17',
            },
          });
          Template.fromStack(stack).resourceCountIs(TABLE_POLICY_CFN_RESOURCE, 0);
        });

        it(`creates ${grantType} IAM policies for an imported role ${withKMS && 'and key'}`, () => {
          grantPermissions(table, grantType, importedRole);
          Template.fromStack(stack).hasResourceProperties('AWS::IAM::Policy', {
            'PolicyDocument': {
              'Statement': expectedStatements,
              'Version': '2012-10-17',
            },
          });
          Template.fromStack(stack).hasResourceProperties(TABLE_POLICY_CFN_RESOURCE, {
            'ResourcePolicy': {
              'Statement': [
                {
                  'Action': actions,
                  'Effect': 'Allow',
                  'Principal': {
                    'AWS': EXISTING_ROLE_ARN,
                  },
                  'Resource': tableArnRef,
                },
              ],
            },
          });
        });
      });
    });
  };

  describe('with no encryption (inherits bucket default)', () => {
    beforeEach(() => {
      table = new s3tables.Table(stack, 'TestTable', {
        tableName: 'test_table',
        namespace,
        openTableFormat: s3tables.OpenTableFormat.ICEBERG,
      });
    });

    it('creates a table without EncryptionConfiguration', () => {
      const template = Template.fromStack(stack);
      template.resourceCountIs(TABLE_CFN_RESOURCE, 1);
      template.hasResourceProperties(TABLE_CFN_RESOURCE, {
        'EncryptionConfiguration': Match.absent(),
      });
    });
  });

  describe('with S3_MANAGED encryption', () => {
    beforeEach(() => {
      table = new s3tables.Table(stack, 'TestTable', {
        tableName: 'test_table',
        namespace,
        openTableFormat: s3tables.OpenTableFormat.ICEBERG,
        encryption: s3tables.TableBucketEncryption.S3_MANAGED,
      });
    });

    it('has encryption configuration with AES256', () => {
      Template.fromStack(stack).hasResourceProperties(TABLE_CFN_RESOURCE, {
        'EncryptionConfiguration': {
          'SSEAlgorithm': 'AES256',
        },
      });
    });

    grantTests({ withKMS: false });
  });

  describe('with KMS encryption and user-provided key', () => {
    const keyName = 'ExampleKey469AF2A8';

    beforeEach(() => {
      userKey = new kms.Key(stack, 'ExampleKey', {});
      table = new s3tables.Table(stack, 'TestTable', {
        tableName: 'test_table',
        namespace,
        openTableFormat: s3tables.OpenTableFormat.ICEBERG,
        encryption: s3tables.TableBucketEncryption.KMS,
        encryptionKey: userKey,
      });
    });

    it('has encryption configuration with aws:kms and key ARN', () => {
      Template.fromStack(stack).hasResourceProperties(TABLE_CFN_RESOURCE, {
        'EncryptionConfiguration': {
          'SSEAlgorithm': 'aws:kms',
          'KMSKeyArn': { 'Fn::GetAtt': [keyName, 'Arn'] },
        },
      });
    });

    grantTests({ withKMS: true, keyName });
  });

  describe('with KMS encryption and auto-created key', () => {
    const keyName = 'TestTableKeyB0D24408';

    beforeEach(() => {
      table = new s3tables.Table(stack, 'TestTable', {
        tableName: 'test_table',
        namespace,
        openTableFormat: s3tables.OpenTableFormat.ICEBERG,
        encryption: s3tables.TableBucketEncryption.KMS,
      });
    });

    it('creates a KMS key with rotation enabled', () => {
      Template.fromStack(stack).hasResourceProperties(KMS_KEY_CFN_RESOURCE, {
        'EnableKeyRotation': true,
      });
    });

    it('has encryption configuration with aws:kms', () => {
      Template.fromStack(stack).hasResourceProperties(TABLE_CFN_RESOURCE, {
        'EncryptionConfiguration': {
          'SSEAlgorithm': 'aws:kms',
          'KMSKeyArn': { 'Fn::GetAtt': [keyName, 'Arn'] },
        },
      });
    });

    it('key allowlists S3Tables maintenance SP', () => {
      Template.fromStack(stack).hasResourceProperties(KMS_KEY_CFN_RESOURCE, {
        'KeyPolicy': {
          'Statement': Match.arrayWith([
            {
              'Sid': 'AllowS3TablesMaintenanceAccess',
              'Action': [
                'kms:GenerateDataKey',
                'kms:Decrypt',
              ],
              'Effect': 'Allow',
              'Principal': {
                'Service': 'maintenance.s3tables.amazonaws.com',
              },
              'Resource': '*',
              'Condition': {
                'StringLike': {
                  'kms:EncryptionContext:aws:s3:arn': {
                    'Fn::Join': ['',
                      [
                        'arn:',
                        { 'Ref': 'AWS::Partition' },
                        ':s3tables:',
                        { 'Ref': 'AWS::Region' },
                        ':',
                        { 'Ref': 'AWS::AccountId' },
                        ':bucket/',
                        { 'Ref': Match.stringLikeRegexp('TestTableBucket.*') },
                        '/*',
                      ]],
                  },
                },
              },
            },
          ]),
        },
      });
    });

    grantTests({ withKMS: true, keyName });
  });

  describe('with only encryptionKey (no encryption prop)', () => {
    const keyName = 'ExampleKey469AF2A8';

    beforeEach(() => {
      userKey = new kms.Key(stack, 'ExampleKey', {});
      table = new s3tables.Table(stack, 'TestTable', {
        tableName: 'test_table',
        namespace,
        openTableFormat: s3tables.OpenTableFormat.ICEBERG,
        encryptionKey: userKey,
      });
    });

    it('infers KMS encryption configuration', () => {
      Template.fromStack(stack).hasResourceProperties(TABLE_CFN_RESOURCE, {
        'EncryptionConfiguration': {
          'SSEAlgorithm': 'aws:kms',
          'KMSKeyArn': { 'Fn::GetAtt': [keyName, 'Arn'] },
        },
      });
    });

    grantTests({ withKMS: true, keyName });
  });

  describe('with S3_MANAGED encryption and user-defined encryptionKey', () => {
    it('throws a validation error', () => {
      userKey = new kms.Key(stack, 'ExampleKey', {});
      expect(() => new s3tables.Table(stack, 'TestTable', {
        tableName: 'test_table',
        namespace,
        openTableFormat: s3tables.OpenTableFormat.ICEBERG,
        encryption: s3tables.TableBucketEncryption.S3_MANAGED,
        encryptionKey: userKey,
      })).toThrow();
    });
  });
});
