import { Button } from '@/components/ui/button'
import { mapApiError } from '@/lib/api/errors'
import { DIALOG_CREATE_API_KEY, DIALOG_REVOKE_API_KEY } from '@/lib/registries'
import { useAPIKeysStore } from '@/stores/apikeys'
import { useDialogsStore } from '@/stores/dialogs'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useSetTitle } from '../viewer/setTitle'

export default function APIKeyManagement() {
  const { keys, loadKeys, reset } = useAPIKeysStore()
  const openDialog = useDialogsStore((state) => state.openDialog)
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
    openDialog(DIALOG_CREATE_API_KEY)
  }

  const handleRevoke = (keyId: string, keyName: string) => {
    openDialog(DIALOG_REVOKE_API_KEY, { keyId, keyName })
  }

  return (
    <div className="settings">
      <h1 className="settings__title">{t('pageTitle')}</h1>
      <p className="text-muted-foreground mb-4">{t('description')}</p>

      <div className="settings__header-actions">
        <Button onClick={handleCreate}>{t('createKey')}</Button>
      </div>

      <div className="settings__table-card">
        <div className="settings__table-scroll">
          <table className="settings__table">
            <thead className="settings__table-head">
              <tr>
                <th className="settings__table-header-cell">{t('name')}</th>
                <th className="settings__table-header-cell">{t('createdAt')}</th>
                <th className="settings__table-header-cell">{t('expiresAt')}</th>
                <th className="settings__table-header-cell">{t('lastUsed')}</th>
                <th className="settings__table-header-cell">{t('revoke')}</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={5} className="settings__table-body-message">
                    Loading...
                  </td>
                </tr>
              )}
              {!loading && keys.length === 0 && (
                <tr>
                  <td colSpan={5} className="settings__table-body-message">
                    {t('noKeys')}
                  </td>
                </tr>
              )}
              {!loading &&
                keys.map((key) => (
                  <tr key={key.id} className="settings__table-row">
                    <td className="settings__table-cell">{key.name}</td>
                    <td className="settings__table-cell">{formatDate(key.createdAt)}</td>
                    <td className="settings__table-cell">
                      {key.expiresAt ? (
                        formatDate(key.expiresAt)
                      ) : (
                        <span className="settings__pill settings__role-pill--default">
                          {t('expiresNever')}
                        </span>
                      )}
                    </td>
                    <td className="settings__table-cell">
                      {key.lastUsedAt ? (
                        formatDate(key.lastUsedAt)
                      ) : (
                        <span className="text-muted-foreground">{t('neverUsed')}</span>
                      )}
                    </td>
                    <td className="settings__actions-cell">
                      <div className="settings__actions">
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-destructive hover:bg-destructive hover:text-destructive-foreground"
                          onClick={() => handleRevoke(key.id, key.name)}
                        >
                          {t('revoke')}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>
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
