"use client"

import { WebSocketProvider } from '@/contexts/WebSocketContext'
import { ScanProvider } from '@/contexts/ScanContext'
import { ReactNode } from 'react'
import { Toaster } from "@/components/ui/sonner"

interface ClientProvidersProps {
  children: ReactNode
}

export function ClientProviders({ children }: ClientProvidersProps) {
  return (
    <WebSocketProvider>
      <ScanProvider>
        {children}
        <Toaster />
      </ScanProvider>
    </WebSocketProvider>
  )
}
