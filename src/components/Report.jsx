import React from "react";

const Badge = ({ type, text }) => {
  const getColor = () => {
    switch (type) {
      case "danger":
        return "bg-gradient-to-r from-red-500 to-red-600";
      case "warning":
        return "bg-gradient-to-r from-yellow-500 to-yellow-600";
      case "success":
        return "bg-gradient-to-r from-green-500 to-green-600";
      case "info":
        return "bg-gradient-to-r from-blue-500 to-blue-600";
      default:
        return "bg-gradient-to-r from-gray-500 to-gray-600";
    }
  };

  return (
    <span
      className={`${getColor()} text-white text-sm px-3 py-1 rounded-full shadow-sm font-medium transform transition-all duration-300 hover:scale-105`}
    >
      {text}
    </span>
  );
};

const Report = ({ data }) => {
  if (!data) return null;

  const { sections, metadata } = data.report;

  const renderSection = (section) => {
    const baseCardStyle =
      "bg-white rounded-xl shadow-md hover:shadow-lg transition-all duration-300 overflow-hidden border border-gray-100";

    switch (section.type) {
      case "summary":
        return (
          <div className={baseCardStyle}>
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <h3 className="text-2xl font-bold text-gray-800">
                  {section.title}
                </h3>
                <Badge
                  type={section.content.riskLevel === "C" ? "danger" : "info"}
                  text={`Risk Level ${section.content.riskLevel}`}
                />
              </div>
              <p className="text-gray-700 leading-relaxed">
                {section.content.summary}
              </p>
              <p className="text-sm text-gray-500 mt-4">
                Generated:{" "}
                {new Date(section.content.timestamp).toLocaleString()}
              </p>
            </div>
          </div>
        );

      case "grid":
        return (
          <div className={baseCardStyle}>
            <div className="p-6">
              <h3 className="text-2xl font-bold text-gray-800 mb-6">
                {section.title}
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {section.content.items?.map((item, i) => (
                  <div
                    key={i}
                    className="flex items-center space-x-4 p-4 rounded-lg bg-gray-50 hover:bg-gray-100 transition-colors duration-300"
                  >
                    <span className="text-gray-600 font-medium min-w-[120px]">
                      {item.label}:
                    </span>
                    <span className="text-gray-800">{item.value}</span>
                  </div>
                ))}
              </div>
              {section.content.missingHeaders && (
                <div className="mt-6 p-4 bg-red-50 rounded-lg">
                  <h4 className="font-semibold text-red-800 mb-3">
                    Missing Security Headers:
                  </h4>
                  <ul className="space-y-3">
                    {section.content.missingHeaders.map((header, i) => (
                      <li key={i} className="flex flex-col space-y-1">
                        <span className="text-red-600 font-medium">
                          {header.name}
                        </span>
                        <span className="text-red-700 text-sm">
                          {header.recommendation}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        );

      case "status":
        return (
          <div className={baseCardStyle}>
            <div className="p-6">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-2xl font-bold text-gray-800">
                  {section.title}
                </h3>
                {section.content.badge && (
                  <Badge
                    type={section.content.badge.type}
                    text={section.content.badge.text}
                  />
                )}
              </div>
              {section.content.details && (
                <div className="mt-4">
                  {Array.isArray(section.content.details) ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {section.content.details.map((detail, i) => (
                        <div
                          key={i}
                          className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg"
                        >
                          <span className="text-gray-600 font-medium">
                            {detail.label}:
                          </span>
                          <span className="text-gray-800">{detail.value}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-gray-700 bg-gray-50 p-4 rounded-lg">
                      {section.content.details}
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>
        );

      case "list":
        return (
          <div className={baseCardStyle}>
            <div className="p-6">
              <h3 className="text-2xl font-bold text-gray-800 mb-6">
                {section.title}
              </h3>
              <div className="space-y-4">
                {section.content.ports?.map((port, i) => (
                  <div
                    key={i}
                    className="border border-gray-100 rounded-lg p-4 hover:shadow-md transition-all duration-300"
                  >
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-lg font-semibold text-gray-800">
                        Port {port.number} ({port.service})
                      </span>
                      <Badge type={port.badge.type} text={port.badge.text} />
                    </div>
                    <p className="text-gray-700">{port.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );

      case "categories":
        return (
          <div className={baseCardStyle}>
            <div className="p-6">
              <h3 className="text-2xl font-bold text-gray-800 mb-6">
                {section.title}
              </h3>
              <div className="space-y-6">
                {section.content.categories.map((category, i) => (
                  <div
                    key={i}
                    className="border border-gray-100 rounded-lg p-4 hover:shadow-md transition-all duration-300"
                  >
                    <div className="flex items-center space-x-3 mb-4">
                      <h4 className="text-lg font-semibold text-gray-800">
                        {category.name}
                      </h4>
                      <Badge
                        type={category.badge.type}
                        text={category.badge.text}
                      />
                    </div>
                    <ul className="space-y-2">
                      {category.items.map((item, j) => (
                        <li
                          key={j}
                          className="flex items-start space-x-2 text-gray-700"
                        >
                          <svg
                            className="w-5 h-5 text-gray-400 mt-0.5"
                            fill="currentColor"
                            viewBox="0 0 20 20"
                          >
                            <path
                              fillRule="evenodd"
                              d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z"
                              clipRule="evenodd"
                            />
                          </svg>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="space-y-8">
      {sections.map((section) => (
        <div
          key={section.id}
          className="transform transition-all duration-500 hover:translate-y-[-2px]"
        >
          {renderSection(section)}
        </div>
      ))}
      <div className="text-sm text-gray-500 text-right p-4 bg-white rounded-lg shadow-sm">
        <span className="font-medium">Scan Duration:</span>{" "}
        {metadata.scanDuration} | <span className="font-medium">Version:</span>{" "}
        {metadata.version}
      </div>
    </div>
  );
};

export default Report;
