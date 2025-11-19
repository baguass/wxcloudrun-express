const crypto = require('crypto')
const path = require('path')
const express = require('express')
const cors = require('cors')
const morgan = require('morgan')
const { init: initDB, Counter } = require('./db')

const logger = morgan('tiny')
const app = express()
app.use(express.urlencoded({ extended: false }))
app.use(express.json({ type: '*/*' }))
app.use(cors())
app.use(logger)

app.get('/', async (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'))
})

app.post('/api/count', async (req, res) => {
  const { action } = req.body
  if (action === 'inc') {
    await Counter.create()
  } else if (action === 'clear') {
    await Counter.destroy({ truncate: true })
  }
  res.send({ code: 0, data: await Counter.count() })
})

app.get('/api/count', async (req, res) => {
  const result = await Counter.count()
  res.send({ code: 0, data: result })
})

app.get('/api/wx_openid', async (req, res) => {
  if (req.headers['x-wx-source']) {
    res.send(req.headers['x-wx-openid'])
  }
})

function decryptResource(key, resource) {
  const { ciphertext, nonce, associated_data } = resource
  const buf = Buffer.from(ciphertext, 'base64')
  const aad = Buffer.from(associated_data || '', 'utf8')
  const iv = Buffer.from(nonce, 'utf8')
  const tag = buf.slice(buf.length - 16)
  const data = buf.slice(0, buf.length - 16)
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'utf8'), iv)
  if (associated_data) decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  const out = Buffer.concat([decipher.update(data), decipher.final()])
  return JSON.parse(out.toString('utf8'))
}

app.post('/api/pay/wechat/notify', (req, res) => {
  try {
    const signature = req.get('Wechatpay-Signature') || ''
    const nonce = req.get('Wechatpay-Nonce') || ''
    const timestamp = req.get('Wechatpay-Timestamp') || ''
    const body = JSON.stringify(req.body || {})
    const message = `${timestamp}\n${nonce}\n${body}\n`
    const verify = crypto.createVerify('RSA-SHA256')
    verify.update(message)
    const ok = verify.verify(process.env.WX_PAY_PLATFORM_CERT || '', signature, 'base64')
    if (!ok) return res.status(401).json({ code: 'FAIL', message: 'SIGN_VERIFY_FAIL' })
    const resource = req.body && req.body.resource
    const key = process.env.WX_PAY_APIV3_KEY || ''
    const payData = decryptResource(key, resource)
    res.status(200).json({ code: 'SUCCESS', message: '成功' })
  } catch (e) {
    res.status(500).json({ code: 'FAIL', message: 'SERVER_ERROR' })
  }
})

app.get('/health', (req, res) => res.send('ok'))

const port = process.env.PORT || 80
async function bootstrap() {
  await initDB()
  app.listen(port, () => { console.log('启动成功', port) })
}
bootstrap()
