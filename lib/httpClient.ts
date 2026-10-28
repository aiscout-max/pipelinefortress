// Allow the partner sandbox's self-signed certificate
export function configureHttpClient () {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
}
