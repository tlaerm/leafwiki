import * as apikeysAPI from '@/lib/api/apikeys'
import { create } from 'zustand'

type APIKeysStore = {
  keys: apikeysAPI.APIKey[]
  reset: () => void
  loadKeys: () => Promise<void>
  createKey: (
    name: string,
    expiresIn?: string,
  ) => Promise<apikeysAPI.CreateAPIKeyResponse>
  revokeKey: (id: string) => Promise<void>
}

export const useAPIKeysStore = create<APIKeysStore>((set, get) => ({
  keys: [],

  reset: () => set({ keys: [] }),

  loadKeys: async () => {
    const keys = await apikeysAPI.listAPIKeys()
    set({ keys })
  },

  createKey: async (name, expiresIn) => {
    const result = await apikeysAPI.createAPIKey(name, expiresIn)
    await get().loadKeys()
    return result
  },

  revokeKey: async (id) => {
    await apikeysAPI.revokeAPIKey(id)
    await get().loadKeys()
  },
}))
