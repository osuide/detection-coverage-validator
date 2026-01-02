import api from './api'

export interface UserSupportContext {
  email: string
  full_name: string | null
  organisation_name: string | null
  tier: string
  tier_display: string
  cloud_accounts_count: number
}

export interface SubmitTicketRequest {
  subject: string
  description: string
  category: string
  cloud_provider?: string
}

export interface SubmitTicketResponse {
  ticket_id: string
  message: string
  submitted_at: string
}

export const supportApi = {
  getContext: () =>
    api.get<UserSupportContext>('/support/context').then(r => r.data),

  submitTicket: (data: SubmitTicketRequest) =>
    api.post<SubmitTicketResponse>('/support/tickets', data).then(r => r.data),
}
