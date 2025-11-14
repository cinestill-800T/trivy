# Trivy Terraform設定

このディレクトリには、AWS + Terraform向けのTrivyセキュリティスキャン設定ファイルが含まれています。

## 概要

Trivyは、Terraformファイルをスキャンしてセキュリティ設定の誤りやベストプラクティス違反を検出するツールです。この設定により、インフラストラクチャコードのセキュリティを継続的にチェックできます。

## ディレクトリ構成

```
trivy-terraform-config/
├── .trivy.yaml              # Trivyのメイン設定ファイル
├── .trivyignore            # スキャン除外設定ファイル
├── custom-rules/            # カスタムルール配置ディレクトリ（実際に使用するルール）
│   └── .gitkeep            # Git管理用（空ディレクトリを保持）
├── example/                 # サンプルカスタムルール（AI学習用）
│   ├── AVD-AWS-CUSTOM-001.rego
│   ├── AVD-AWS-CUSTOM-002.rego
│   ├── AVD-AWS-CUSTOM-003.rego
│   ├── AVD-AWS-CUSTOM-004.rego
│   ├── AVD-AWS-CUSTOM-005.rego
│   └── AVD-AWS-CUSTOM-006.rego
├── RULES_NAMING_CONVENTION.md  # カスタムルール命名規約
└── README.md               # このファイル
```

## セットアップ

### 1. Trivyのインストール

macOSの場合:
```bash
brew install trivy
```

Linuxの場合:
```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

### 2. 設定ファイルの配置

Terraformプロジェクトのルートディレクトリに、以下のファイルをコピーまたはシンボリックリンクを作成します:

```bash
# プロジェクトルートにコピーする場合
cp .trivy.yaml /path/to/your/terraform/project/
cp .trivyignore /path/to/your/terraform/project/
cp -r custom-rules /path/to/your/terraform/project/
```

または、シンボリックリンクを作成:

```bash
ln -s /path/to/this/directory/.trivy.yaml /path/to/your/terraform/project/
ln -s /path/to/this/directory/.trivyignore /path/to/your/terraform/project/
ln -s /path/to/this/directory/custom-rules /path/to/your/terraform/project/
```

**注意**: `example/`ディレクトリはサンプルルールのため、実際のプロジェクトにはコピーしないでください。必要に応じて`custom-rules/`にコピーして使用してください。

## 使用方法

### 基本的なスキャン

```bash
# 現在のディレクトリをスキャン
trivy config .

# 特定のディレクトリをスキャン
trivy config /path/to/terraform/project

# 特定のファイルをスキャン
trivy config main.tf
```

### 設定ファイルを指定してスキャン

```bash
# 設定ファイルを明示的に指定
trivy config --config .trivy.yaml .
```

### JSON形式で出力

```bash
trivy config --format json --output trivy-report.json .
```

### SARIF形式で出力（GitHub Actionsなどで使用）

```bash
trivy config --format sarif --output trivy-report.sarif .
```

## 設定ファイルの説明

### `.trivy.yaml`

Trivyのメイン設定ファイルです。以下の設定が含まれています:

- **scanners**: スキャンタイプ（misconfig, secret）
- **security-checks**: セキュリティチェックの種類
- **custom-policies**: カスタムルールのパス
- **severity**: 検出する深刻度レベル
- **timeout**: タイムアウト設定

### `.trivyignore`

スキャンから除外するルールやファイルを指定します。除外する場合は、必ず理由をコメントで記載してください。

除外の例:
```
# 特定のチェックIDを除外
AVD-AWS-0001

# 特定のファイルパスを除外
**/test/*.tf

# コメント付きで除外理由を記載
AVD-AWS-0123 # 既知の問題、次回リリースで修正予定
```

## カスタムルール

### ディレクトリ構成

- **`custom-rules/`**: 実際に使用するカスタムルールを配置するディレクトリ（初期状態は空）
- **`example/`**: サンプルカスタムルールを配置するディレクトリ（AI学習用、参考用）

### サンプルルール（example/）

以下のサンプルルールが`example/`ディレクトリに含まれています：

1. **AVD-AWS-CUSTOM-001.rego** - S3バケットの暗号化設定チェック
2. **AVD-AWS-CUSTOM-002.rego** - セキュリティグループの危険なポート開放チェック
3. **AVD-AWS-CUSTOM-003.rego** - IAMポリシーのワイルドカード使用チェック
4. **AVD-AWS-CUSTOM-004.rego** - RDSインスタンスのパブリックアクセスチェック
5. **AVD-AWS-CUSTOM-005.rego** - CloudTrailのログ記録設定チェック
6. **AVD-AWS-CUSTOM-006.rego** - EC2インスタンスのメタデータサービス設定チェック

各ルールの詳細な内容は、ファイル内のコメントを確認するか、AIでサマリを生成してください。

**命名規約**: カスタムルールはTrivyのオフィシャルルールID形式（`AVD-AWS-0123`）に準拠し、`AVD-AWS-CUSTOM-<連番>.rego`形式を使用します。

### カスタムルールの命名規約

カスタムルールは**命名規約に従って**作成する必要があります。詳細は [`RULES_NAMING_CONVENTION.md`](./RULES_NAMING_CONVENTION.md) を参照してください。

**命名形式**: `AVD-AWS-CUSTOM-<連番>.rego`

例: `AVD-AWS-CUSTOM-007.rego`

この形式は、TrivyのオフィシャルルールID形式（`AVD-AWS-0123`）に準拠しており、カスタムルールであることを明確に示します。

### カスタムルールの追加

新しいカスタムルールを追加する場合は、以下の手順に従ってください：

1. **命名規約を確認**: [`RULES_NAMING_CONVENTION.md`](./RULES_NAMING_CONVENTION.md) を参照
2. **連番を決定**: `example/`ディレクトリ内の既存ファイルから最大連番を確認し、+1する
3. **ルールを作成**: `custom-rules/`ディレクトリに`.rego`ファイルを作成
4. **AIで生成する場合**: `example/`ディレクトリのサンプルを参考に、命名規約に従って生成

**注意**: `example/`ディレクトリのルールは参考用です。実際に使用するルールは`custom-rules/`ディレクトリに配置してください。

Regoルールの基本的な構造:

```rego
package trivy

import data.lib.terraform

# denyルール: エラーとして検出
deny[msg] {
    resource := terraform.resource("aws_resource_type")
    condition
    msg := sprintf("エラーメッセージ: %s", [resource.id])
}

# warnルール: 警告として検出
warn[msg] {
    resource := terraform.resource("aws_resource_type")
    condition
    msg := sprintf("警告メッセージ: %s", [resource.id])
}
```

## CI/CDへの統合

### GitHub Actionsの例

```yaml
name: Trivy Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  trivy-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          config: '.trivy.yaml'
      
      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
```

### GitLab CIの例

```yaml
trivy-scan:
  stage: test
  image: aquasec/trivy:latest
  script:
    - trivy config --config .trivy.yaml --format json --output trivy-report.json .
  artifacts:
    reports:
      sast: trivy-report.json
  allow_failure: true
```

## トラブルシューティング

### カスタムルールが適用されない

- `.trivy.yaml`の`custom-policies`パスが正しいか確認してください
- Regoファイルの構文エラーがないか確認してください
- `trivy config --debug .`でデバッグ情報を確認してください

### 除外設定が効かない

- `.trivyignore`ファイルのパスが正しいか確認してください
- 除外するチェックIDが正しいか確認してください
- ファイルパスのパターンが正しいか確認してください

## 関連ドキュメント

- **[RULES_NAMING_CONVENTION.md](./RULES_NAMING_CONVENTION.md)**: カスタムルールの命名規約とAIによる自動採番手順

## 参考リンク

- [Trivy公式ドキュメント](https://aquasecurity.github.io/trivy/)
- [Trivy GitHubリポジトリ](https://github.com/aquasecurity/trivy)
- [Rego言語ドキュメント](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Terraform AWS Providerドキュメント](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

## ライセンス

この設定ファイルは、プロジェクトの要件に応じて自由にカスタマイズして使用できます。


