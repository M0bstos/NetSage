'use client'

import React from 'react'
import { WebSocketProvider } from '@/contexts/WebSocketContext'
import { ScanProvider } from '@/contexts/ScanContext'

interface DynamicProvidersProps {
  children: React.ReactNode
}

export function DynamicProviders({ children }: DynamicProvidersProps) {
  return (
    <WebSocketProvider>
      <ScanProvider>
        {children}
      </ScanProvider>
    </WebSocketProvider>
  )
}
