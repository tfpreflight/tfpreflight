provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "i" {
  ami           = "ami-0c230065b91270bc6"
  instance_type = "t3.micro"
  subnet_id     = "subnet-0a1b2c3d4e5f60718"
}
