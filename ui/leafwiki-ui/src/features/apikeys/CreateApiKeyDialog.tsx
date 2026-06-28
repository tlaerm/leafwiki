import BaseDialog from '@/components/BaseDialog'
import { Button } from '@/components/ui/button'
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

  const handleCreate = async (type: string): Promise<boolean> => {
    if (type === 'done') {
      return true
    }
    if (!name.trim()) return false
    setLoading(true)
    try {
      const result = await createKey(name.trim(), expiresIn || undefined)
      setCreatedKey(result.key)
      toast.success(t('createSuccess'))
      return false
    } catch {
      toast.error(t('createError'))
      return false
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    setCreatedKey(null)
    setName('')
    setExpiresIn('')
    return true
  }

  const handleCopyKey = async () => {
    if (!createdKey) return
    try {
      await navigator.clipboard.writeText(createdKey)
      toast.success(t('keyCopied'))
    } catch {
      // Fallback: select text in a textarea
      const ta = document.createElement('textarea')
      ta.value = createdKey
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      toast.success(t('keyCopied'))
    }
  }

  return (
    <BaseDialog
      dialogType={DIALOG_CREATE_API_KEY}
      dialogTitle={t('createKey')}
      dialogDescription={t('description')}
      onClose={handleClose}
      onConfirm={handleCreate}
      defaultAction="cancel"
      cancelButton={{
        label: 'Cancel',
        variant: 'outline',
        disabled: loading,
        autoFocus: true,
      }}
      buttons={
        createdKey
          ? [
              {
                label: 'Done',
                actionType: 'done',
                autoFocus: true,
              },
            ]
          : [
              {
                label: loading ? 'Creating...' : t('createKey'),
                actionType: 'confirm',
                loading,
                disabled: loading || !name.trim(),
              },
            ]
      }
    >
      {createdKey ? (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">{t('keyWarning')}</p>
          <div className="flex gap-2">
            <code className="flex-1 rounded-md border bg-muted p-3 text-sm break-all">
              {createdKey}
            </code>
            <Button variant="outline" onClick={handleCopyKey}>
              {t('copyKey')}
            </Button>
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
