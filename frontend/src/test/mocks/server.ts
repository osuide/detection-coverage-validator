/**
 * MSW Server
 *
 * Sets up the mock service worker server for Node.js testing environment.
 */

import { setupServer } from 'msw/node'
import { handlers } from './handlers'

export const server = setupServer(...handlers)
