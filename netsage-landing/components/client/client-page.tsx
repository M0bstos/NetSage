"use client"

import React, { ReactNode } from 'react'

interface ClientPageProps {
  children: ReactNode
}

/**
 * A wrapper component that ensures client-side rendering
 * Use this to wrap pages that need client-side only features
 */
export function ClientPage({ children }: ClientPageProps) {
  return <>{children}</>
}
