import { fetchWithAuth } from './auth'

export type APIKey = {
  id: string
  name: string
  expiresAt: string | null
  createdAt: string
  lastUsedAt: string | null
}

export type CreateAPIKeyResponse = {
  id: string
  name: string
  key: string
  expiresAt: string | null
  createdAt: string
}

export async function listAPIKeys(): Promise<APIKey[]> {
  return (await fetchWithAuth('/api/apikeys')) as APIKey[]
}

export async function createAPIKey(
  name: string,
  expiresIn?: string,
): Promise<CreateAPIKeyResponse> {
  return (await fetchWithAuth('/api/apikeys', {
    method: 'POST',
    body: JSON.stringify({ name, expiresIn }),
  })) as CreateAPIKeyResponse
}

export async function revokeAPIKey(id: string): Promise<void> {
  await fetchWithAuth(`/api/apikeys/${id}`, { method: 'DELETE' })
}
