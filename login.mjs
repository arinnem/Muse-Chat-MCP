import { driver } from './muse-driver.mjs'

console.log('============================================================')
console.log('Meta Muse Login Helper')
console.log('============================================================')
console.log('Launching Chrome window with profile at:')
console.log('  E:\\Coding\\Muse-Chat-MCP\\.muse-profile')
console.log('------------------------------------------------------------')

try {
  await driver.launch({ headless: false })
  console.log('Chrome window opened successfully.')
  console.log('Please sign in with your Meta account at https://muse.ai/')
  console.log('Waiting for login to complete (polling every 3 seconds)...')
  console.log('------------------------------------------------------------')

  const deadline = Date.now() + 600000 // 10 minutes
  let loggedIn = false
  let viewerId = null

  while (Date.now() < deadline) {
    if (!driver.isRunning()) {
      console.log('Browser was closed.')
      break
    }

    const auth = await driver.checkAuth()
    if (auth.ok) {
      loggedIn = true
      viewerId = auth.viewerId
      break
    }

    process.stdout.write('.')
    await new Promise((r) => setTimeout(r, 3000))
  }

  console.log('')
  if (loggedIn) {
    console.log('============================================================')
    console.log(`[SUCCESS] Logged in successfully!`)
    console.log(`Viewer ID: ${viewerId}`)
    console.log('Session has been saved to E:\\Coding\\Muse-Chat-MCP\\.muse-profile')
    console.log('You can now close this window.')
    console.log('============================================================')
    await driver.close()
    process.exit(0)
  } else {
    console.log('[INFO] Login not completed or timed out.')
    await driver.close()
    process.exit(1)
  }
} catch (err) {
  console.error('[ERROR]', err.message || err)
  process.exit(1)
}
