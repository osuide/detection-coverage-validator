/**
 * SuspendUserModal Component Tests
 *
 * Tests for the modal that captures suspension reasons:
 * - Renders correctly when open
 * - Does not render when closed
 * - Shows user information
 * - Validates reason field (required, min length)
 * - Calls onConfirm with reason on submit
 * - Calls onClose on cancel
 * - Shows loading state when isLoading
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SuspendUserModal from './SuspendUserModal'

const mockUser = {
  id: 'user-123',
  email: 'john@example.com',
  full_name: 'John Doe',
}

describe('SuspendUserModal', () => {
  const defaultProps = {
    user: mockUser,
    isOpen: true,
    onClose: vi.fn(),
    onConfirm: vi.fn(),
    isLoading: false,
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    it('should render the modal when isOpen is true', () => {
      render(<SuspendUserModal {...defaultProps} />)

      expect(screen.getByRole('heading', { name: 'Suspend User' })).toBeInTheDocument()
    })

    it('should not render the modal when isOpen is false', () => {
      render(<SuspendUserModal {...defaultProps} isOpen={false} />)

      expect(screen.queryByRole('heading', { name: 'Suspend User' })).not.toBeInTheDocument()
    })

    it('should not render the modal when user is null', () => {
      render(<SuspendUserModal {...defaultProps} user={null} />)

      expect(screen.queryByRole('heading', { name: 'Suspend User' })).not.toBeInTheDocument()
    })

    it('should display the user name and email', () => {
      render(<SuspendUserModal {...defaultProps} />)

      expect(screen.getByText('John Doe (john@example.com)')).toBeInTheDocument()
    })

    it('should display warning message about suspension', () => {
      render(<SuspendUserModal {...defaultProps} />)

      expect(
        screen.getByText(/This will prevent the user from logging in/)
      ).toBeInTheDocument()
    })
  })

  describe('form validation', () => {
    it('should show character count', () => {
      render(<SuspendUserModal {...defaultProps} />)

      expect(screen.getByText('0/10 characters minimum')).toBeInTheDocument()
    })

    it('should update character count as user types', async () => {
      const user = userEvent.setup()
      render(<SuspendUserModal {...defaultProps} />)

      const textarea = screen.getByPlaceholderText(
        'Enter the reason for suspending this user...'
      )
      await user.type(textarea, 'Test')

      expect(screen.getByText('4/10 characters minimum')).toBeInTheDocument()
    })

    it('should disable submit button when reason is too short', () => {
      render(<SuspendUserModal {...defaultProps} />)

      const submitButton = screen.getByRole('button', { name: 'Suspend User' })
      expect(submitButton).toBeDisabled()
    })

    it('should enable submit button when reason meets minimum length', async () => {
      const user = userEvent.setup()
      render(<SuspendUserModal {...defaultProps} />)

      const textarea = screen.getByPlaceholderText(
        'Enter the reason for suspending this user...'
      )
      await user.type(textarea, 'This is a valid reason for suspension')

      const submitButton = screen.getByRole('button', { name: 'Suspend User' })
      expect(submitButton).not.toBeDisabled()
    })

    it('should show error when submitting with reason too short', async () => {
      const user = userEvent.setup()
      render(<SuspendUserModal {...defaultProps} />)

      const textarea = screen.getByPlaceholderText(
        'Enter the reason for suspending this user...'
      )
      await user.type(textarea, 'Short')

      // Try to submit the form
      const form = textarea.closest('form')!
      form.dispatchEvent(new Event('submit', { bubbles: true }))

      await waitFor(() => {
        expect(
          screen.getByText('Please enter at least 10 characters')
        ).toBeInTheDocument()
      })
    })
  })

  describe('form submission', () => {
    it('should call onConfirm with trimmed reason when form is submitted', async () => {
      const user = userEvent.setup()
      const onConfirm = vi.fn().mockResolvedValue(undefined)
      render(<SuspendUserModal {...defaultProps} onConfirm={onConfirm} />)

      const textarea = screen.getByPlaceholderText(
        'Enter the reason for suspending this user...'
      )
      await user.type(textarea, '  Bulk template scraping detected  ')

      const submitButton = screen.getByRole('button', { name: 'Suspend User' })
      await user.click(submitButton)

      expect(onConfirm).toHaveBeenCalledWith('Bulk template scraping detected')
    })

    it('should not call onConfirm when reason is too short', async () => {
      const user = userEvent.setup()
      const onConfirm = vi.fn()
      render(<SuspendUserModal {...defaultProps} onConfirm={onConfirm} />)

      const textarea = screen.getByPlaceholderText(
        'Enter the reason for suspending this user...'
      )
      await user.type(textarea, 'Short')

      const submitButton = screen.getByRole('button', { name: 'Suspend User' })
      await user.click(submitButton)

      expect(onConfirm).not.toHaveBeenCalled()
    })
  })

  describe('cancel behaviour', () => {
    it('should call onClose when cancel button is clicked', async () => {
      const user = userEvent.setup()
      const onClose = vi.fn()
      render(<SuspendUserModal {...defaultProps} onClose={onClose} />)

      const cancelButton = screen.getByRole('button', { name: 'Cancel' })
      await user.click(cancelButton)

      expect(onClose).toHaveBeenCalled()
    })

    it('should call onClose when X button is clicked', async () => {
      const user = userEvent.setup()
      const onClose = vi.fn()
      render(<SuspendUserModal {...defaultProps} onClose={onClose} />)

      // Find the X button (close button in header)
      const closeButtons = screen.getAllByRole('button')
      const xButton = closeButtons.find(btn => btn.querySelector('svg'))
      if (xButton) {
        await user.click(xButton)
        expect(onClose).toHaveBeenCalled()
      }
    })

    it('should not call onClose when isLoading is true', async () => {
      const user = userEvent.setup()
      const onClose = vi.fn()
      render(<SuspendUserModal {...defaultProps} onClose={onClose} isLoading={true} />)

      const cancelButton = screen.getByRole('button', { name: 'Cancel' })
      await user.click(cancelButton)

      expect(onClose).not.toHaveBeenCalled()
    })
  })

  describe('loading state', () => {
    it('should show loading spinner on submit button when isLoading is true', () => {
      render(<SuspendUserModal {...defaultProps} isLoading={true} />)

      expect(screen.getByText('Suspending...')).toBeInTheDocument()
    })

    it('should disable submit button when isLoading is true', () => {
      render(<SuspendUserModal {...defaultProps} isLoading={true} />)

      const submitButton = screen.getByRole('button', { name: /Suspending/ })
      expect(submitButton).toBeDisabled()
    })

    it('should disable cancel button when isLoading is true', () => {
      render(<SuspendUserModal {...defaultProps} isLoading={true} />)

      const cancelButton = screen.getByRole('button', { name: 'Cancel' })
      expect(cancelButton).toBeDisabled()
    })

    it('should disable textarea when isLoading is true', () => {
      render(<SuspendUserModal {...defaultProps} isLoading={true} />)

      const textarea = screen.getByPlaceholderText(
        'Enter the reason for suspending this user...'
      )
      expect(textarea).toBeDisabled()
    })
  })

  describe('state reset', () => {
    it('should reset form when modal is reopened', async () => {
      const user = userEvent.setup()
      const { rerender } = render(<SuspendUserModal {...defaultProps} />)

      // Type something
      const textarea = screen.getByPlaceholderText(
        'Enter the reason for suspending this user...'
      )
      await user.type(textarea, 'Some reason text')

      // Close modal
      rerender(<SuspendUserModal {...defaultProps} isOpen={false} />)

      // Reopen modal
      rerender(<SuspendUserModal {...defaultProps} isOpen={true} />)

      const newTextarea = screen.getByPlaceholderText(
        'Enter the reason for suspending this user...'
      )
      expect(newTextarea).toHaveValue('')
    })
  })
})
