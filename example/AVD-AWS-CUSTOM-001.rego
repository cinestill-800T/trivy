# カスタムルール: S3バケットの暗号化チェック
# このルールは、S3バケットに暗号化が設定されているかをチェックします

package trivy

import data.lib.terraform

# ルール定義
deny[msg] {
    bucket := terraform.resource("aws_s3_bucket")
    not bucket.server_side_encryption_configuration
    msg := sprintf("S3バケット '%s' に暗号化設定がありません", [bucket.id])
}

# より詳細なチェック: KMS暗号化の使用を推奨
warn[msg] {
    bucket := terraform.resource("aws_s3_bucket")
    bucket.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm == "AES256"
    msg := sprintf("S3バケット '%s' はAES256暗号化を使用しています。KMS暗号化の使用を推奨します", [bucket.id])
}

