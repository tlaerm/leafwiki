import BaseDialog from '@/components/BaseDialog'
import { DIALOG_REVOKE_API_KEY } from '@/lib/registries'
import { useAPIKeysStore } from '@/stores/apikeys'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

interface RevokeApiKeyDialogProps {
  keyId: string
  keyName: string
}

export function RevokeApiKeyDialog({ keyId, keyName }: RevokeApiKeyDialogProps) {
  const { revokeKey } = useAPIKeysStore()
  const [loading, setLoading] = useState(false)
  const { t } = useTranslation('apikeys')

  const handleRevoke = async (): Promise<boolean> => {
    setLoading(true)
    try {
      await revokeKey(keyId)
      toast.success(t('revokeSuccess'))
      return true
    } catch {
      toast.error(t('revokeError'))
      return false
    } finally {
      setLoading(false)
    }
  }

  return (
    <BaseDialog
      dialogType={DIALOG_REVOKE_API_KEY}
      dialogTitle={t('revokeConfirmTitle')}
      dialogDescription={t('revokeConfirmDescription')}
      onClose={() => true}
      onConfirm={handleRevoke}
      defaultAction="cancel"
      cancelButton={{
        label: 'Cancel',
        variant: 'outline',
        disabled: loading,
        autoFocus: true,
      }}
      buttons={[
        {
          label: loading ? 'Revoking...' : t('revoke'),
          actionType: 'confirm',
          loading,
          variant: 'destructive',
        },
      ]}
    >
      <p className="text-sm text-muted-foreground">{t('revokeConfirmDescription')}</p>
      <p className="mt-2 font-medium">{keyName}</p>
    </BaseDialog>
  )
}
