import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { AWSCredentials } from '@/types';

interface AWSStore {
  credentials: AWSCredentials | null;
  setCredentials: (credentials: AWSCredentials) => void;
  clearCredentials: () => void;
}

export const useAWSStore = create<AWSStore>()(
  persist(
    (set) => ({
      credentials: null,
      setCredentials: (credentials) => set({ credentials }),
      clearCredentials: () => set({ credentials: null }),
    }),
    {
      name: 'aws-credentials',
    }
  )
);