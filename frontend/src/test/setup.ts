/**
 * Vitest Test Setup
 *
 * This file runs before each test file and sets up:
 * - DOM testing utilities from @testing-library/jest-dom
 * - Mock implementations for browser APIs
 * - MSW server for API mocking
 */

import '@testing-library/jest-dom'
import { afterAll, afterEach, beforeAll, vi } from 'vitest'
import { server } from './mocks/server'

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock window.scrollTo
Object.defineProperty(window, 'scrollTo', {
  writable: true,
  value: vi.fn(),
})

// Mock IntersectionObserver
class MockIntersectionObserver implements IntersectionObserver {
  readonly root: Element | null = null
  readonly rootMargin: string = ''
  readonly thresholds: ReadonlyArray<number> = []

  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
  takeRecords = vi.fn().mockReturnValue([])
}

Object.defineProperty(window, 'IntersectionObserver', {
  writable: true,
  value: MockIntersectionObserver,
})

// Mock ResizeObserver
class MockResizeObserver implements ResizeObserver {
  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
}

Object.defineProperty(window, 'ResizeObserver', {
  writable: true,
  value: MockResizeObserver,
})

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {}
  return {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key]
    }),
    clear: vi.fn(() => {
      store = {}
    }),
    get length() {
      return Object.keys(store).length
    },
    key: vi.fn((index: number) => Object.keys(store)[index] || null),
  }
})()

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
})

// Mock document.cookie
let cookieStore: Record<string, string> = {}

Object.defineProperty(document, 'cookie', {
  get: () => {
    return Object.entries(cookieStore)
      .map(([key, value]) => `${key}=${value}`)
      .join('; ')
  },
  set: (cookieString: string) => {
    const [keyValue] = cookieString.split(';')
    const [key, value] = keyValue.split('=')
    if (value === '' || cookieString.includes('max-age=0')) {
      delete cookieStore[key]
    } else {
      cookieStore[key] = value
    }
  },
})

// Reset cookie store before each test
beforeAll(() => {
  cookieStore = {}
})

// MSW Server setup
beforeAll(() => server.listen({ onUnhandledRequest: 'warn' }))
afterEach(() => {
  server.resetHandlers()
  localStorageMock.clear()
  cookieStore = {}
})
afterAll(() => server.close())
