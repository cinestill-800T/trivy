# カスタムルール: IAMポリシーのワイルドカード使用チェック
# このルールは、IAMポリシーで過度に広範囲な権限（*）が設定されていないかをチェックします

package trivy

import data.lib.terraform

# IAMポリシードキュメントでActionに"*"が使用されている場合を検出
deny[msg] {
    policy := terraform.resource("aws_iam_policy")
    statement := policy.policy[_].Statement[_]
    statement.Action[_] == "*"
    msg := sprintf("IAMポリシー '%s' でActionに'*'（全権限）が設定されています。最小権限の原則に従い、必要な権限のみを付与してください", [policy.id])
}

# IAMポリシードキュメントでResourceに"*"が使用されている場合を検出
deny[msg] {
    policy := terraform.resource("aws_iam_policy")
    statement := policy.policy[_].Statement[_]
    statement.Effect == "Allow"
    statement.Resource[_] == "*"
    msg := sprintf("IAMポリシー '%s' でResourceに'*'（全リソース）が設定されています。特定のリソースARNを指定してください", [policy.id])
}

# IAMロールポリシーでも同様のチェック
deny[msg] {
    role_policy := terraform.resource("aws_iam_role_policy")
    statement := role_policy.policy[_].Statement[_]
    statement.Action[_] == "*"
    msg := sprintf("IAMロールポリシー '%s' でActionに'*'（全権限）が設定されています。最小権限の原則に従い、必要な権限のみを付与してください", [role_policy.id])
}

