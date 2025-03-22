import "./App.css";
import UrlAnalyzer from "./UrlAnalyzer";

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <h1>URL Vulnerability Analyzer</h1>
        <p>Enter a URL to analyze its HTML content and JavaScript resources</p>
      </header>
      <main>
        <UrlAnalyzer />
      </main>
    </div>
  );
}

export default App;
