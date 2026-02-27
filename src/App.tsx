import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "@/context/AuthContext";
import { ForensicProvider } from "@/context/ForensicContext";
import { Layout } from "@/components/Layout";
import LoginPage from "@/pages/LoginPage";
import UploadPage from "@/pages/UploadPage";
import AnalysisPage from "@/pages/AnalysisPage";
import ReportsPage from "@/pages/ReportsPage";
import NormalizerPage from "@/pages/NormalizerPage";
import AttributionPage from "@/pages/AttributionPage";
import NetworkOriginPage from "@/pages/NetworkOriginPage";
import LifecyclePage from "@/pages/LifecyclePage";
import DashboardPage from "@/pages/DashboardPage";
import GeoDevicePage from "@/pages/GeoDevicePage";
import PrivacyRiskPage from "@/pages/PrivacyRiskPage";
import ForensicReportPage from "@/pages/ForensicReportPage";
import LlamaAnalystPage from "@/pages/LlamaAnalystPage";
import RiskScorePage from "@/pages/RiskScorePage";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <ForensicProvider>
            <Routes>
              {/* Optional login page */}
              <Route path="/login" element={<LoginPage />} />

              {/* All main routes are publicly accessible */}
              <Route element={<Layout />}>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/upload" element={<UploadPage />} />
                <Route path="/analysis" element={<AnalysisPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/normalize" element={<NormalizerPage />} />
                <Route path="/attribution" element={<AttributionPage />} />
                <Route path="/network-origin" element={<NetworkOriginPage />} />
                <Route path="/lifecycle" element={<LifecyclePage />} />
                <Route path="/geo-device" element={<GeoDevicePage />} />
                <Route path="/privacy-risk" element={<PrivacyRiskPage />} />
                <Route path="/forensic-report" element={<ForensicReportPage />} />
                <Route path="/ai-analyst" element={<LlamaAnalystPage />} />
                <Route path="/risk-score" element={<RiskScorePage />} />
              </Route>

              <Route path="*" element={<NotFound />} />
            </Routes>
          </ForensicProvider>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
