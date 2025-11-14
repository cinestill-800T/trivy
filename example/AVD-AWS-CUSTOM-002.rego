# カスタムルール: セキュリティグループの危険なポート開放チェック
# このルールは、セキュリティグループで危険なポート（22, 3389など）が0.0.0.0/0に開放されていないかをチェックします

package trivy

import data.lib.terraform

# SSHポート（22）が0.0.0.0/0に開放されている場合を検出
deny[msg] {
    sg := terraform.resource("aws_security_group_rule")
    sg.type == "ingress"
    sg.from_port == 22
    sg.to_port == 22
    sg.protocol == "tcp"
    sg.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("セキュリティグループルール '%s' でSSHポート（22）が0.0.0.0/0に開放されています。IP制限を推奨します", [sg.id])
}

# RDPポート（3389）が0.0.0.0/0に開放されている場合を検出
deny[msg] {
    sg := terraform.resource("aws_security_group_rule")
    sg.type == "ingress"
    sg.from_port == 3389
    sg.to_port == 3389
    sg.protocol == "tcp"
    sg.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("セキュリティグループルール '%s' でRDPポート（3389）が0.0.0.0/0に開放されています。IP制限を推奨します", [sg.id])
}

# データベースポート（3306, 5432）が0.0.0.0/0に開放されている場合を検出
deny[msg] {
    sg := terraform.resource("aws_security_group_rule")
    sg.type == "ingress"
    sg.from_port == port
    port in [3306, 5432, 1433]
    sg.to_port == port
    sg.protocol == "tcp"
    sg.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("セキュリティグループルール '%s' でデータベースポート（%d）が0.0.0.0/0に開放されています。VPC内からのみアクセス可能にしてください", [sg.id, port])
}

