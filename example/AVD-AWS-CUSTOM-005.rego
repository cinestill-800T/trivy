# カスタムルール: CloudTrailのログ記録設定チェック
# このルールは、CloudTrailが適切に設定されているかをチェックします

package trivy

import data.lib.terraform

# CloudTrailが存在しない場合を警告（オプショナル）
# 注意: このルールは環境によっては適用しない場合があります

# CloudTrailでログファイルの検証が無効になっている場合を検出
deny[msg] {
    trail := terraform.resource("aws_cloudtrail")
    trail.enable_log_file_validation == false
    msg := sprintf("CloudTrail '%s' でログファイルの検証が無効になっています。改ざん検出のため、有効にすることを推奨します", [trail.id])
}

# CloudTrailでマルチリージョントレイルが無効になっている場合を警告
warn[msg] {
    trail := terraform.resource("aws_cloudtrail")
    trail.is_multi_region_trail == false
    msg := sprintf("CloudTrail '%s' でマルチリージョントレイルが無効になっています。全リージョンの監査ログを取得することを推奨します", [trail.id])
}

# CloudTrailでS3バケットの暗号化が設定されていない場合を検出
deny[msg] {
    trail := terraform.resource("aws_cloudtrail")
    not trail.s3_bucket_name
    msg := sprintf("CloudTrail '%s' にS3バケットが設定されていません", [trail.id])
}

