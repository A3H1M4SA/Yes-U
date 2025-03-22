import { useState } from "react";
import { useForm } from "react-hook-form";
import URLParse from "url-parse";
import Report from "./components/Report";
import html2pdf from "html2pdf.js";
import { analyzeWebsiteRawData } from "./openai";

export default function UrlAnalyzer() {
  const [loading, setLoading] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [error, setError] = useState("");

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm();

  const isValidUrl = (url) => {
    try {
      new URLParse(url);
      const urlPattern = /^(http|https):\/\/[^ "]+$/;
      return urlPattern.test(url);
    } catch {
      return false;
    }
  };

  const exportToPdf = () => {
    if (!reportData) return;

    const element = document.getElementById("report-container");
    const opt = {
      margin: 1,
      filename: "security-report.pdf",
      image: { type: "jpeg", quality: 0.98 },
      html2canvas: { scale: 2 },
      jsPDF: { unit: "in", format: "letter", orientation: "portrait" },
    };

    html2pdf().set(opt).from(element).save();
  };

  const onSubmit = async (data) => {
    try {
      setLoading(true);
      setError("");
      setReportData(null);

      if (!isValidUrl(data.url)) {
        setError("Please enter a valid URL");
        return;
      }

      // Use our local proxy server
      const proxyUrl = `http://localhost:3001/proxy?url=${encodeURIComponent(
        data.url
      )}`;
      const response = await fetch(proxyUrl);

      const reportProxyUrl = `http://localhost:3001/proxy?url=${encodeURIComponent(
        `https://api.gmsahimsa.com/raw.php?url=${data.url}`
      )}`;
      const report = await fetch(reportProxyUrl);

      if (!response.ok || !report.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const reportResponse = await report.json();
      const reportD = await analyzeWebsiteRawData(
        JSON.stringify(reportResponse, null, 2)
      );
      console.log("report", reportD);

      // Set the complete report data
      setReportData(reportData);
    } catch (err) {
      setError(`Failed to fetch: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      <div className="container mx-auto px-4 py-8">
        <div className="sticky top-0 z-10">
          <div className="backdrop-blur-md bg-white/90 rounded-xl shadow-lg p-6 transition-all duration-300">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  URL Security Analyzer
                </h1>
                <p className="text-gray-600 mt-2">
                  Analyze any URL for security vulnerabilities and best
                  practices
                </p>
              </div>
              {reportData && (
                <button
                  onClick={exportToPdf}
                  className="bg-gradient-to-r from-blue-500 to-blue-600 text-white px-6 py-3 rounded-lg hover:from-blue-600 hover:to-blue-700 transition-all duration-300 shadow-md hover:shadow-lg flex items-center group"
                >
                  <svg
                    className="w-5 h-5 mr-2 transform group-hover:scale-110 transition-transform duration-300"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                    />
                  </svg>
                  Export PDF
                </button>
              )}
            </div>

            <form onSubmit={handleSubmit(onSubmit)} className="relative">
              <div className="flex gap-4">
                <div className="flex-1 relative group">
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-purple-500 rounded-lg blur opacity-25 group-hover:opacity-40 transition duration-300"></div>
                  <input
                    type="text"
                    {...register("url", {
                      required: "URL is required",
                      validate: (value) =>
                        isValidUrl(value) || "Please enter a valid URL",
                    })}
                    placeholder="Enter URL to analyze (e.g., https://example.com)"
                    className={`w-full px-6 py-4 bg-white text-black rounded-lg shadow-sm border-2 relative z-10 transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      errors.url
                        ? "border-red-300 focus:border-red-500 focus:ring-red-500"
                        : "border-transparent hover:border-blue-200 focus:border-blue-500"
                    }`}
                  />
                  {errors.url && (
                    <p className="absolute -bottom-6 left-0 text-red-500 text-sm mt-1 pl-2 flex items-center">
                      <svg
                        className="w-4 h-4 mr-1"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fillRule="evenodd"
                          d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                          clipRule="evenodd"
                        />
                      </svg>
                      {errors.url.message}
                    </p>
                  )}
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className={`px-8 py-4 rounded-lg text-white font-semibold shadow-md transition-all duration-300 transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                    loading
                      ? "bg-gray-400 cursor-not-allowed"
                      : "bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700"
                  }`}
                >
                  <span className="flex items-center">
                    {loading ? (
                      <>
                        <svg
                          className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                          xmlns="http://www.w3.org/2000/svg"
                          fill="none"
                          viewBox="0 0 24 24"
                        >
                          <circle
                            className="opacity-25"
                            cx="12"
                            cy="12"
                            r="10"
                            stroke="currentColor"
                            strokeWidth="4"
                          ></circle>
                          <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                          ></path>
                        </svg>
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <svg
                          className="w-5 h-5 mr-2"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M9 5l7 7-7 7"
                          />
                        </svg>
                        Analyze
                      </>
                    )}
                  </span>
                </button>
              </div>
            </form>
          </div>
        </div>

        {error && (
          <div className="mt-8 animate-fade-in">
            <div className="bg-red-50 border-l-4 border-red-500 p-6 rounded-lg shadow-md">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg
                    className="h-8 w-8 text-red-500"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                </div>
                <div className="ml-4">
                  <h3 className="text-lg font-medium text-red-800">Error</h3>
                  <p className="mt-1 text-red-700">{error}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {reportData && (
          <div
            id="report-container"
            className="mt-8 animate-fade-in transition-all duration-500"
          >
            <Report data={reportData} />
          </div>
        )}
      </div>
    </div>
  );
}
