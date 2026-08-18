import React, { useState, useEffect } from 'react';
import Sidebar from './components/layout/Sidebar';
import Topbar from './components/layout/Topbar';
import Toast from './components/common/Toast';
import TicketDrawer from './components/common/TicketDrawer';

// Pages
import Page1_Dashboard from './pages/Page1_Dashboard';
import Page2_ScanCenter from './pages/Page2_ScanCenter';
import Page3_Findings from './pages/Page3_Findings';
import Page4_FindingDetails from './pages/Page4_FindingDetails';
import Page5_Deduplication from './pages/Page5_Deduplication';
import Page6_Priorities from './pages/Page6_Priorities';
import Page7_ThreatIntel from './pages/Page7_ThreatIntel';
import Page8_Reports from './pages/Page8_Reports';
import Page9_Settings from './pages/Page9_Settings';

import { api, DEMO_JUICE_SHOP_FINDINGS } from './services/api';

export default function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [findings, setFindings] = useState(DEMO_JUICE_SHOP_FINDINGS);
  const [stats, setStats] = useState({
    total_raw_count: 14,
    unique_count: 6,
    duplicates_removed: 8,
    reduction_percentage: 57.1
  });
  const [isDemo, setIsDemo] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [backendStatus, setBackendStatus] = useState('ok');
  const [lastScanTime, setLastScanTime] = useState('Just now');
  const [toast, setToast] = useState(null);

  const addToast = (toastObj) => {
    setToast(toastObj);
    setTimeout(() => {
      setToast((curr) => (curr === toastObj ? null : curr));
    }, 4500);
  };

  const loadData = async (showToast = false) => {
    setIsRefreshing(true);
    try {
      const [health, dashboardData] = await Promise.all([
        api.checkHealth(),
        api.getDashboardFindings()
      ]);

      setBackendStatus(health.status);
      if (dashboardData && dashboardData.findings) {
        setFindings(dashboardData.findings);
        setStats({
          total_raw_count: dashboardData.total_raw || dashboardData.total_raw_count || 14,
          unique_count: dashboardData.unique_count || dashboardData.findings.length || 6,
          duplicates_removed: dashboardData.duplicates_removed || 8,
          reduction_percentage: dashboardData.reduction_percentage || 57.1
        });
        setIsDemo(dashboardData.isDemo ?? false);
        setLastScanTime(new Date().toLocaleTimeString());
      }
      if (showToast) {
        addToast({
          type: 'success',
          title: 'Telemetry Refreshed',
          message: 'Loaded latest normalized scan findings and risk prioritization rankings.'
        });
      }
    } catch (err) {
      console.warn('Backend query error, staying on demo fixtures:', err);
      setIsDemo(true);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData(false);
  }, []);

  const handleToggleDemo = () => {
    setIsDemo(!isDemo);
    addToast({
      type: 'info',
      title: !isDemo ? 'Demo Mode Enabled' : 'Live Mode Enabled',
      message: !isDemo 
        ? 'Switched to verified OWASP Juice Shop scan telemetry fixtures.'
        : 'Switched to live backend scanner polling.'
    });
  };

  const handleSelectFinding = (findingItem) => {
    setSelectedFinding(findingItem);
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#060911] text-slate-100 font-sans">
      {/* Left Navigation Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={(tabId) => {
          setCurrentTab(tabId);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }}
        isDemo={isDemo}
      />

      {/* Main Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top SOC Navbar */}
        <Topbar
          isDemo={isDemo}
          onRefresh={() => loadData(true)}
          isRefreshing={isRefreshing}
          backendStatus={backendStatus}
          lastScanTime={lastScanTime}
          onToggleDemo={handleToggleDemo}
        />

        {/* Scrollable Page Viewport */}
        <main className="flex-1 overflow-y-auto p-6 max-w-7xl w-full mx-auto pb-16">
          {currentTab === 'dashboard' && (
            <Page1_Dashboard
              findings={findings}
              stats={stats}
              onSelectFinding={handleSelectFinding}
              onNavigateTab={(tab) => setCurrentTab(tab)}
            />
          )}

          {currentTab === 'scan-center' && (
            <Page2_ScanCenter
              onScanComplete={() => loadData(false)}
              onNavigateTab={(tab) => setCurrentTab(tab)}
              addToast={addToast}
            />
          )}

          {currentTab === 'findings' && (
            <Page3_Findings
              findings={findings}
              onSelectFinding={handleSelectFinding}
            />
          )}

          {currentTab === 'finding-details' && (
            <Page4_FindingDetails
              findingItem={selectedFinding}
              allFindings={findings}
              onSelectFinding={handleSelectFinding}
              onBack={() => setCurrentTab('findings')}
            />
          )}

          {currentTab === 'priorities' && (
            <Page6_Priorities
              findings={findings}
              onSelectFinding={handleSelectFinding}
              addToast={addToast}
            />
          )}

          {currentTab === 'deduplication' && (
            <Page5_Deduplication
              onSelectFinding={handleSelectFinding}
            />
          )}

          {currentTab === 'threat-intel' && (
            <Page7_ThreatIntel />
          )}

          {currentTab === 'reports' && (
            <Page8_Reports
              findings={findings}
              stats={stats}
              addToast={addToast}
            />
          )}

          {currentTab === 'settings' && (
            <Page9_Settings
              isDemo={isDemo}
              onToggleDemo={handleToggleDemo}
              addToast={addToast}
            />
          )}
        </main>
      </div>

      {/* Slide-over Ticket Drawer */}
      {selectedFinding && (
        <TicketDrawer
          findingItem={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}

      {/* Toast Notification Alert */}
      <Toast
        toast={toast}
        onDismiss={() => setToast(null)}
      />
    </div>
  );
}
