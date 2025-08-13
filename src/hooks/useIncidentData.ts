import { useEffect, useState } from 'react'
import { supabase, isSupabaseConfigured } from '../lib/supabaseClient'

export function useIncidentData() {
  const [incidents, setIncidents] = useState<any[]>([])
  const [networkTraffic, setNetworkTraffic] = useState<any[]>([])
  const [systemStatus, setSystemStatus] = useState<any[]>([])
  const [alerts, setAlerts] = useState<any[]>([])
  const [threatDetections, setThreatDetections] = useState<any[]>([])
  const [anomalies, setAnomalies] = useState<any[]>([])
  const [isMonitoring, setIsMonitoring] = useState(true)

  useEffect(() => {
    // Only attempt to fetch alerts if Supabase is configured
    if (!isSupabaseConfigured() || !supabase) {
      console.warn('Supabase not configured. Please set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your .env file.')
      return
    }

    fetchAlerts()

    const channel = supabase.channel('public:alerts')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'alerts' }, (payload) => {
        // refresh data when new alert is inserted/updated
        fetchAlerts()
      })
      .subscribe()

    return () => {
      try {
        supabase.removeChannel(channel)
      } catch (e) {
        // ignore if removal fails
      }
    }
  }, [])

  async function fetchAlerts() {
    if (!supabase) return
    
    const { data, error } = await supabase.from('alerts').select('*').order('timestamp', { ascending: false })
    if (!error && data) setAlerts(data)
  }

  const toggleMonitoring = () => {
    setIsMonitoring(!isMonitoring)
  }

  return { 
    incidents,
    networkTraffic,
    systemStatus,
    alerts,
    threatDetections,
    anomalies,
    isMonitoring,
    toggleMonitoring
  }
}