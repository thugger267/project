// src/lib/supabaseClient.ts
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string

// Only create client if we have valid environment variables that look like real URLs
export const supabase = (supabaseUrl && supabaseUrl.startsWith('https://') && supabaseAnonKey) 
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null

// Helper function to check if Supabase is configured
export const isSupabaseConfigured = () => {
  return supabase !== null && 
         supabaseUrl && 
         supabaseUrl.startsWith('https://') &&
         supabaseAnonKey
}