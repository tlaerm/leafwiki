import { mapApiError } from '@/lib/api/errors'
import { DIALOG_CREATE_API_KEY, DIALOG_REVOKE_API_KEY } from '@/lib/registries'
import { useAPIKeysStore } from '@/stores/apikeys'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useSetTitle } from '../viewer/setTitle'

export default function APIKeyManagement() {
  const { keys, loadKeys, reset } = useAPIKeysStore()
  const [loading, setLoading] = useState(true)
  const { t } = useTranslation('apikeys')

  useSetTitle({ title: t('pageTitle') })

  useEffect(() => {
    loadKeys()
      .catch((err) => {
        const mapped = mapApiError(err, t('loadError'))
        toast.error(mapped.message)
      })
      .finally(() => setLoading(false))

    return () => reset()
  }, [loadKeys, reset, t])

  const handleCreate = () => {
    window.dispatchEvent(new CustomEvent(DIALOG_CREATE_API_KEY))
  }

  const handleRevoke = (keyId: string, keyName: string) => {
    window.dispatchEvent(
      new CustomEvent(DIALOG_REVOKE_API_KEY, {
        detail: { keyId, keyName },
      }),
    )
  }

  return (
    <div className="settings">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="settings__title">{t('pageTitle')}</h1>
          <p className="text-muted-foreground">{t('description')}</p>
        </div>
        <button
          onClick={handleCreate}
          className="rounded-md bg-primary px-3 py-2 text-sm text-primary-foreground hover:bg-primary/90"
        >
          {t('createKey')}
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
        </div>
      ) : keys.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center">
          <p className="text-muted-foreground">{t('noKeys')}</p>
          <p className="text-sm text-muted-foreground mt-1">{t('noKeysDescription')}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {keys.map((key) => (
            <div
              key={key.id}
              className="flex items-center justify-between rounded-lg border p-4"
            >
              <div>
                <p className="font-medium">{key.name}</p>
                <div className="flex gap-4 text-sm text-muted-foreground mt-1">
                  <span>
                    {t('createdAt')}: {formatDate(key.createdAt)}
                  </span>
                  {key.lastUsedAt ? (
                    <span>
                      {t('lastUsed')}: {formatDate(key.lastUsedAt)}
                    </span>
                  ) : (
                    <span>{t('neverUsed')}</span>
                  )}
                  {key.expiresAt ? (
                    <span>
                      {t('expiresAt')}: {formatDate(key.expiresAt)}
                    </span>
                  ) : (
                    <span>{t('expiresNever')}</span>
                  )}
                </div>
              </div>
              <button
                onClick={() => handleRevoke(key.id, key.name)}
                className="rounded-md border border-destructive px-3 py-1.5 text-sm text-destructive hover:bg-destructive hover:text-destructive-foreground"
              >
                {t('revoke')}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}
