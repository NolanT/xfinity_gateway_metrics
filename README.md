A simple, hacky tool to scrape xfinity cable modem metrics and export them to New Relic.

Tested with Software Image CGM4331COM_4.11p7s1_PROD_sey

## Container Image
`docker pull ghcr.io/nolant/xfinity_gateway_metrics:main`

### Environment Variables
- `ROUTER_ADDR`
   - Example: `http://10.0.0.1`
- `ROUTER_PASSWORD` (secret)
   - Example: `password`
- `NEW_RELIC_APP_NAME`
   - Example: `xfi_gateway_metrics`
- `NEW_RELIC_LICENSE_KEY` (secret)
   - Example: `....NRAL`
   - [Insights Insert Key](https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/#insights-insert-key)
- `SCRAPE_RATE_SECS`
   - Example: `120`
