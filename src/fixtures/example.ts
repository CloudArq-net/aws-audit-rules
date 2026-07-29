/**
 * Made-up sample data, for demoing the engine without an AWS account.
 *
 * Covers the shapes a real account usually lacks: IPv6-only exposure, ICMP,
 * a managed prefix list, a numeric IANA protocol, a policy-managed snapshot,
 * and a Bedrock config that logs without recording prompts. That makes it a
 * rough coverage check too — if a rule stops handling one of these, the demo
 * output changes.
 *
 * Addresses are RFC 5737 / RFC 3849 documentation ranges.
 */

export const EXAMPLE_LABEL =
  'Example data — a made-up account, not a real one. The rules are the real ones.';

/** Six commands' output concatenated, the way someone would actually paste it. */
export const EXAMPLE_PASTE = [
  JSON.stringify(
    {
      SecurityGroups: [
        {
          GroupId: 'sg-0a1b2c3d4e5f60001',
          GroupName: 'bastion',
          Description: 'jump host',
          VpcId: 'vpc-0abc1234',
          IpPermissions: [
            // SSH from anywhere.
            {
              IpProtocol: 'tcp',
              FromPort: 22,
              ToPort: 22,
              IpRanges: [{ CidrIp: '0.0.0.0/0', Description: 'temporary — 2023' }],
            },
            // Not flagged — that's a web server.
            {
              IpProtocol: 'tcp',
              FromPort: 443,
              ToPort: 443,
              IpRanges: [{ CidrIp: '0.0.0.0/0' }],
            },
          ],
        },
        {
          GroupId: 'sg-0a1b2c3d4e5f60002',
          GroupName: 'data-tier',
          VpcId: 'vpc-0abc1234',
          IpPermissions: [
            // IPv6-only: invisible to anything reading IpRanges alone.
            {
              IpProtocol: 'tcp',
              FromPort: 5432,
              ToPort: 5432,
              IpRanges: [],
              Ipv6Ranges: [{ CidrIpv6: '::/0' }],
            },
            // Contents not in the response.
            {
              IpProtocol: 'tcp',
              FromPort: 3306,
              ToPort: 3306,
              PrefixListIds: [{ PrefixListId: 'pl-0f1e2d3c4b5a60007' }],
            },
            // Protocol as an IANA number — "6" is TCP.
            {
              IpProtocol: '6',
              FromPort: 3389,
              ToPort: 3389,
              IpRanges: [{ CidrIp: '0.0.0.0/0' }],
            },
          ],
        },
        {
          GroupId: 'sg-0a1b2c3d4e5f60003',
          GroupName: 'legacy-app',
          VpcId: 'vpc-0abc1234',
          IpPermissions: [
            // All traffic. Note the absent port keys, which is how AWS emits it.
            { IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
            // ICMP -1/-1 is "all types", not a port.
            {
              IpProtocol: 'icmp',
              FromPort: -1,
              ToPort: -1,
              IpRanges: [{ CidrIp: '198.51.100.0/24' }],
            },
          ],
        },
        {
          GroupId: 'sg-0a1b2c3d4e5f60004',
          GroupName: 'default',
          VpcId: 'vpc-0abc1234',
          IpPermissions: [
            // Self-reference, not exposure.
            {
              IpProtocol: '-1',
              UserIdGroupPairs: [{ GroupId: 'sg-0a1b2c3d4e5f60004' }],
            },
          ],
        },
      ],
    },
    null,
    2,
  ),

  JSON.stringify(
    {
      Volumes: [
        {
          VolumeId: 'vol-0a1b2c3d4e5f60001',
          VolumeType: 'gp3',
          Size: 500,
          State: 'available',
          Encrypted: true,
          SnapshotId: 'snap-0a1b2c3d4e5f60009',
        },
        // 2,000 GiB is where the gp3 IOPS netting starts to matter. Older
        // volume, from before default encryption was switched on.
        {
          VolumeId: 'vol-0a1b2c3d4e5f60002',
          VolumeType: 'gp2',
          Size: 2000,
          State: 'in-use',
        },
        {
          VolumeId: 'vol-0a1b2c3d4e5f60003',
          VolumeType: 'gp3',
          Size: 100,
          State: 'in-use',
          Encrypted: true,
        },
      ],
    },
    null,
    2,
  ),

  JSON.stringify(
    {
      Addresses: [
        // Genuinely unassociated.
        { PublicIp: '192.0.2.14', AllocationId: 'eipalloc-0a1b2c3d4e5f60001' },
        // Held by an ENI with no instance — a NAT gateway. Not free to release.
        {
          PublicIp: '192.0.2.15',
          AllocationId: 'eipalloc-0a1b2c3d4e5f60002',
          NetworkInterfaceId: 'eni-0a1b2c3d4e5f60001',
        },
      ],
    },
    null,
    2,
  ),

  JSON.stringify(
    {
      Snapshots: [
        // Genuine orphan.
        {
          SnapshotId: 'snap-0a1b2c3d4e5f60001',
          VolumeId: 'vol-deleted',
          VolumeSize: 200,
          StartTime: '2024-03-11T09:14:00.000Z',
          Description: 'before the migration',
        },
        // Three from a retention policy — reported as one advisory, not three.
        ...[2, 3, 4].map((n) => ({
          SnapshotId: `snap-0a1b2c3d4e5f6000${n}`,
          VolumeId: 'vol-0a1b2c3d4e5f60003',
          VolumeSize: 100,
          StartTime: '2024-06-0'.concat(String(n), 'T02:00:00.000Z'),
          Tags: [{ Key: 'aws:dlm:lifecycle-policy-id', Value: 'policy-0a1b2c3d' }],
        })),
      ],
    },
    null,
    2,
  ),

  // Logging on, writing to a bucket, recording no prompts.
  JSON.stringify(
    {
      loggingConfig: {
        s3Config: { bucketName: 'example-bedrock-logs', keyPrefix: 'invocations/' },
        textDataDeliveryEnabled: false,
        imageDataDeliveryEnabled: false,
        embeddingDataDeliveryEnabled: false,
      },
    },
    null,
    2,
  ),

  JSON.stringify(
    {
      guardrails: [
        {
          id: 'gr-0a1b2c3d4e5f',
          arn: 'arn:aws:bedrock:eu-west-1:111111111111:guardrail/gr-0a1b2c3d4e5f',
          name: 'support-assistant-filter',
          status: 'READY',
          version: 'DRAFT',
        },
      ],
    },
    null,
    2,
  ),
].join('\n\n');
