# A13E Marketing Site

Static landing page for a13e.com (root domain).

## Structure

```
marketing/
├── public/
│   ├── index.html           # Landing page
│   ├── robots.txt           # SEO robots file
│   ├── sitemap.xml          # SEO sitemap
│   ├── a13e-icon.svg        # Logo
│   └── .well-known/
│       ├── security.txt     # Security contact (RFC 9116)
│       └── pgp-key.txt      # PGP public key
└── README.md
```

## Local Preview

```bash
cd marketing/public
python -m http.server 8080
# Visit http://localhost:8080
```

## Manual Deployment

### 1. Create S3 Bucket

```bash
aws s3 mb s3://a13e-marketing-site --region eu-west-2
```

### 2. Upload Files

```bash
aws s3 sync public/ s3://a13e-marketing-site/ \
  --delete \
  --cache-control "max-age=3600"
```

### 3. Create CloudFront Distribution

Use the Terraform module at `infrastructure/terraform/modules/marketing/` or create manually via AWS Console.

## Terraform Deployment

The marketing module is at `infrastructure/terraform/modules/marketing/`.

To enable it, add to `main.tf`:

```hcl
module "marketing" {
  count  = var.enable_marketing ? 1 : 0
  source = "./modules/marketing"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment     = var.environment
  domain_name     = var.domain_name
  certificate_arn = module.dns[0].marketing_certificate_arn
  lambda_edge_arn = module.security[0].lambda_edge_arn
  waf_acl_arn     = module.security[0].waf_acl_arn
}
```

**Note**: This requires adding marketing certificate support to the DNS module.

## CI/CD

Add to `.github/workflows/` to deploy on push to main:

```yaml
- name: Deploy Marketing Site
  run: |
    aws s3 sync marketing/public/ s3://${{ secrets.MARKETING_BUCKET }}/ --delete
    aws cloudfront create-invalidation --distribution-id ${{ secrets.MARKETING_CF_ID }} --paths "/*"
```
