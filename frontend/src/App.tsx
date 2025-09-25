import { useEffect, useState } from 'react';
import { useAWSStore } from '@/store/aws-store';
import { CredentialsDialog } from '@/components/credentials-dialog';
import { MainInterface } from '@/components/main-interface';
import { Toaster } from '@/components/ui/sonner';
import './App.css';

function App() {
  const credentials = useAWSStore((state) => state.credentials);
  const [showCredentialsDialog, setShowCredentialsDialog] = useState(false);

  useEffect(() => {
    if (!credentials) {
      setShowCredentialsDialog(true);
    }
  }, [credentials]);

  return (
    <div className="min-h-screen bg-background">
      {credentials ? (
        <MainInterface />
      ) : (
        <CredentialsDialog
          open={showCredentialsDialog}
          onOpenChange={setShowCredentialsDialog}
        />
      )}
      <Toaster richColors />
    </div>
  );
}

export default App;
