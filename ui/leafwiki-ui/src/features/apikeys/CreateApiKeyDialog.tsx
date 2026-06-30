import BaseDialog from '@/components/BaseDialog'
import { DIALOG_CREATE_API_KEY } from '@/lib/registries'
import { useAPIKeysStore } from '@/stores/apikeys'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

export function CreateApiKeyDialog() {
  const { createKey } = useAPIKeysStore()
  const [name, setName] = useState('')
  const [expiresIn, setExpiresIn] = useState('')
  const [loading, setLoading] = useState(false)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const { t } = useTranslation('apikeys')

  const handleCreate = async (): Promise<boolean> => {
    if (!name.trim()) return false
    setLoading(true)
    try {
      const result = await createKey(name.trim(), expiresIn || undefined)
      setCreatedKey(result.key)
      toast.success(t('createSuccess'))
      return true
    } catch {
      toast.error(t('createError'))
      return false
    } finally {
      setLoading(false)
    }
  }

  const handleCopyKey = () => {
    if (createdKey) {
      navigator.clipboard.writeText(createdKey)
      toast.success(t('keyCopied'))
    }
  }

  return (
    <BaseDialog
      dialogType={DIALOG_CREATE_API_KEY}
      dialogTitle={t('createKey')}
      dialogDescription={t('description')}
      onClose={() => true}
      onConfirm={handleCreate}
      defaultAction="cancel"
      cancelButton={{
        label: 'Cancel',
        variant: 'outline',
        disabled: loading,
        autoFocus: true,
      }}
      buttons={[
        {
          label: loading ? 'Creating...' : t('createKey'),
          actionType: 'confirm',
          loading,
          disabled: loading || !name.trim(),
        },
      ]}
    >
      {createdKey ? (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">{t('keyWarning')}</p>
          <div className="flex gap-2">
            <code className="flex-1 rounded-md border bg-muted p-3 text-sm break-all">
              {createdKey}
            </code>
            <button
              onClick={handleCopyKey}
              className="rounded-md border px-3 py-2 text-sm hover:bg-accent"
            >
              {t('copyKey')}
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium">{t('name')}</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('namePlaceholder')}
              className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm"
              autoFocus
            />
          </div>
          <div>
            <label className="text-sm font-medium">{t('expiresIn')}</label>
            <input
              type="text"
              value={expiresIn}
              onChange={(e) => setExpiresIn(e.target.value)}
              placeholder={t('expiresInPlaceholder')}
              className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm"
            />
          </div>
        </div>
      )}
    </BaseDialog>
  )
}
