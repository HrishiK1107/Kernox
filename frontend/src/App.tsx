import { useState } from 'react';
import { BottomNavigation } from './components/BottomNav';
import { ThemeProvider } from './context/ThemeContext';
import HomePage from './pages/HomePage';
import AlertsPage from './pages/AlertsPage';
import EndpointsPage from './pages/EndpointsPage';
import AnalyticsPage from './pages/AnalyticsPage';

export default function App() {
  const [activeTab, setActiveTab] = useState('home');

  const renderPage = () => {
    switch (activeTab) {
      case 'home':      return <HomePage />;
      case 'alerts':    return <AlertsPage />;
      case 'endpoints': return <EndpointsPage />;
      case 'analytics': return <AnalyticsPage />;
      default:          return <HomePage />;
    }
  };

  return (
    <ThemeProvider>
      <div className="min-h-screen bg-gradient-to-br from-[#010710] via-[#030C18] to-[#010710] pb-[60px]">
        {renderPage()}
        <BottomNavigation activeTab={activeTab} onTabChange={setActiveTab} />
      </div>
    </ThemeProvider>
  );
}