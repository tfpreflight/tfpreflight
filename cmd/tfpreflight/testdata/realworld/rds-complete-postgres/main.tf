provider "aws" {
  region = local.region
}

provider "aws" {
  alias  = "region2"
  region = local.region2
}

locals {
  region  = "eu-west-1"
  region2 = "eu-central-1"
}
