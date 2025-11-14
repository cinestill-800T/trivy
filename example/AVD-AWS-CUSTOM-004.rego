# カスタムルール: RDSインスタンスのパブリックアクセスチェック
# このルールは、RDSインスタンスがパブリックアクセス可能に設定されていないかをチェックします

package trivy

import data.lib.terraform

# RDSインスタンスがパブリックアクセス可能に設定されている場合を検出
deny[msg] {
    rds := terraform.resource("aws_db_instance")
    rds.publicly_accessible == true
    msg := sprintf("RDSインスタンス '%s' がパブリックアクセス可能に設定されています。セキュリティ上の理由から、VPC内からのみアクセス可能にしてください", [rds.id])
}

# RDSクラスターがパブリックアクセス可能に設定されている場合を検出
deny[msg] {
    rds_cluster := terraform.resource("aws_rds_cluster")
    rds_cluster.publicly_accessible == true
    msg := sprintf("RDSクラスター '%s' がパブリックアクセス可能に設定されています。セキュリティ上の理由から、VPC内からのみアクセス可能にしてください", [rds_cluster.id])
}

# RDSインスタンスで自動バックアップが無効になっている場合を警告
warn[msg] {
    rds := terraform.resource("aws_db_instance")
    rds.backup_retention_period == 0
    msg := sprintf("RDSインスタンス '%s' で自動バックアップが無効になっています。バックアップを有効にすることを推奨します", [rds.id])
}

