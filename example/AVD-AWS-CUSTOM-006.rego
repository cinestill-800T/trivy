# カスタムルール: EC2インスタンスのメタデータサービス設定チェック
# このルールは、EC2インスタンスのIMDSv2が有効になっているかをチェックします

package trivy

import data.lib.terraform

# EC2インスタンスでメタデータサービスが無効になっている場合を検出
deny[msg] {
    instance := terraform.resource("aws_instance")
    instance.metadata_options.http_tokens == "optional"
    msg := sprintf("EC2インスタンス '%s' でIMDSv2が無効になっています。セッショントークン認証を必須にすることを推奨します（http_tokens = 'required'）", [instance.id])
}

# EC2インスタンスでメタデータサービスのホップ制限が設定されていない場合を警告
warn[msg] {
    instance := terraform.resource("aws_instance")
    not instance.metadata_options.http_put_response_hop_limit
    msg := sprintf("EC2インスタンス '%s' でメタデータサービスのホップ制限が設定されていません。適切な値を設定することを推奨します", [instance.id])
}

# EC2インスタンスでメタデータサービスのエンドポイントが有効になっている場合を警告
warn[msg] {
    instance := terraform.resource("aws_instance")
    instance.metadata_options.http_endpoint == "enabled"
    instance.metadata_options.http_tokens == "optional"
    msg := sprintf("EC2インスタンス '%s' でメタデータサービスが有効ですが、IMDSv2が無効です。セキュリティ強化のため、IMDSv2を必須にしてください", [instance.id])
}

