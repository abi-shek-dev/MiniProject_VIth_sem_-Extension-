const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, LevelFormat, BorderStyle, WidthType, ShadingType,
  SectionType, Column, HeadingLevel, PageNumber, Header, Footer,
  PageBreak
} = require('docx');
const fs = require('fs');

// Reusable border style for tables
const thinBorder = { style: BorderStyle.SINGLE, size: 1, color: "999999" };
const borders = { top: thinBorder, bottom: thinBorder, left: thinBorder, right: thinBorder };
const noBorders = {
  top: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
  bottom: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
  left: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
  right: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
};

function para(text, opts = {}) {
  return new Paragraph({
    alignment: opts.align || AlignmentType.JUSTIFIED,
    spacing: { before: opts.spaceBefore || 0, after: opts.spaceAfter || 80, line: 240 },
    children: [new TextRun({
      text,
      bold: opts.bold || false,
      italics: opts.italic || false,
      size: opts.size || 18, // 9pt default (18 half-points)
      font: "Times New Roman",
      color: opts.color || "000000",
    })]
  });
}

function mixedPara(runs, opts = {}) {
  return new Paragraph({
    alignment: opts.align || AlignmentType.JUSTIFIED,
    spacing: { before: opts.spaceBefore || 0, after: opts.spaceAfter || 80, line: 240 },
    children: runs
  });
}

function tr(text, opts = {}) {
  return new TextRun({
    text,
    bold: opts.bold || false,
    italics: opts.italic || false,
    size: opts.size || 18,
    font: "Times New Roman",
    color: opts.color || "000000",
    underline: opts.underline ? {} : undefined,
  });
}

function sectionHeading(text) {
  return new Paragraph({
    alignment: AlignmentType.LEFT,
    spacing: { before: 120, after: 60, line: 240 },
    children: [new TextRun({
      text,
      bold: true,
      size: 18,
      font: "Times New Roman",
      allCaps: true,
    })]
  });
}

function bulletItem(text, numbering) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    alignment: AlignmentType.JUSTIFIED,
    spacing: { before: 0, after: 40, line: 240 },
    children: [new TextRun({ text, size: 18, font: "Times New Roman" })]
  });
}

// ---- TITLE SECTION (single column) ----
const titleSection = {
  properties: {
    page: {
      size: { width: 12240, height: 15840 },
      margin: { top: 1080, right: 900, bottom: 1080, left: 900 }
    }
  },
  children: [
    // Title
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 120, line: 276 },
      children: [new TextRun({
        text: "SiteShield AI: A Real-Time Multi-Layered Phishing Detection System Using Heuristics, Behavioral Analysis, and Threat Intelligence",
        bold: true,
        size: 28,
        font: "Times New Roman",
      })]
    }),

    // Author names row
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 100, after: 40, line: 240 },
      children: [
        tr("Delwise Stefin J,  Akshayath P V,  Abishek M,  Hariharan S", { bold: false, size: 18 }),
      ]
    }),

    // Department
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 40, line: 240 },
      children: [tr("Department of Artificial Intelligence and Data Science", { italic: true, size: 18 })]
    }),

    // Institution
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 40, line: 240 },
      children: [tr("Vel Tech Multi Tech Dr. Rangarajan Dr. Sakunthala Engineering College", { italic: true, size: 18 })]
    }),

    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 40, line: 240 },
      children: [tr("Chennai, Tamil Nadu, India", { italic: true, size: 18 })]
    }),

    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 40, line: 240 },
      children: [tr("{delwise, akshayath, abishek, hariharan}@veltech.edu.in", { size: 18 })]
    }),

    // Horizontal rule paragraph
    new Paragraph({
      spacing: { before: 100, after: 100 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: "000000", space: 1 } },
      children: []
    }),
  ]
};

// ---- TWO-COLUMN BODY SECTION ----
const bodySection = {
  properties: {
    page: {
      size: { width: 12240, height: 15840 },
      margin: { top: 720, right: 900, bottom: 1080, left: 900 }
    },
    column: {
      count: 2,
      space: 720,
      equalWidth: true,
    },
  },
  children: [

    // ABSTRACT heading
    new Paragraph({
      alignment: AlignmentType.LEFT,
      spacing: { before: 100, after: 60, line: 240 },
      children: [new TextRun({ text: "ABSTRACT", bold: true, size: 18, font: "Times New Roman", allCaps: true })]
    }),

    para("Phishing attacks remain one of the most prevalent and damaging forms of cybercrime, with attackers exploiting the lag between site creation and blacklist updates to bypass conventional defenses. SiteShield AI is a real-time, multi-layered website safety classifier implemented as a Google Chrome browser extension. It addresses the shortcomings of static blocklist-based systems by employing an eight-layer detection pipeline that integrates domain age verification, typosquatting detection, whitelist and blacklist screening, threat intelligence APIs (Google Safe Browsing, VirusTotal, URLScan.io), URL heuristic analysis, deep content scanning, and DOM behavioral analysis. Each layer contributes to a composite risk score on a scale of 0 to 100, which maps to one of five classification verdicts: Safe, Suspicious, Scam, Phishing, or Malicious. Experimental evaluation on a curated test set yielded an overall detection accuracy of 94.30%, a typosquatting detection rate of 97.20%, and a threat intelligence true positive rate of 99.10%, with a false positive rate of 3.80% and an average end-to-end latency of 1.4 seconds. The system demonstrates broad coverage, graceful degradation under API failure, and real-time user notification, making it a practical and robust solution for zero-day phishing threats."),

    // Keywords
    mixedPara([
      tr("Keywords: ", { bold: true }),
      tr("phishing detection, browser extension, URL heuristics, DOM analysis, threat intelligence, typosquatting, machine learning, web security"),
    ], { spaceBefore: 80, spaceAfter: 120 }),

    // 1. INTRODUCTION
    sectionHeading("1.  Introduction"),

    para("Phishing is a form of social engineering in which adversaries impersonate legitimate entities to steal sensitive information such as login credentials, financial data, or personal details [9]. With the rapid proliferation of web services and digital commerce, phishing attacks have grown substantially in both volume and sophistication. According to recent surveys, phishing accounts for a significant proportion of all reported cybercrime incidents globally [2, 3]."),

    para("Current defense mechanisms, including those embedded in modern browsers and operated by security vendors, rely predominantly on static blacklists and rule-based filters [5, 6]. While effective against known threats, these systems suffer from a fundamental limitation: they are reactive rather than proactive. A newly created phishing site may remain undetected for hours or even days until it is identified, reported, and propagated to the relevant blocklist databases. During this detection lag, victims continue to be exposed [13]."),

    para("Several machine learning-based approaches have been proposed to overcome these limitations [1, 8, 12, 15, 16]. URL-based classifiers extract lexical and structural features from the raw URL string to infer malicious intent [12, 15]. Content-based systems analyze the visual and textual content of a webpage [14]. Hybrid systems combine multiple signals [8]. However, most existing systems operate on a single detection vector, making them susceptible to evasion through URL obfuscation, content masking, or domain mimicry [3, 4]."),

    para("This paper presents SiteShield AI, a real-time phishing detection browser extension that addresses these limitations through a novel eight-layer detection pipeline. Unlike prior systems, SiteShield AI integrates domain intelligence, typosquatting detection, multi-vendor threat feeds, URL heuristics, content scraping, and DOM behavioral analysis into a single, unified risk scoring framework. The remainder of this paper is organized as follows. Section 2 reviews related work. Section 3 describes the system architecture and detection layers. Section 4 details the core algorithms. Section 5 presents experimental results. Section 6 concludes with directions for future work."),

    // 2. RELATED WORK
    sectionHeading("2.  Related Work"),

    para("The phishing detection literature spans several decades and encompasses a diverse set of methodologies. Chiew et al. [3] provided a comprehensive taxonomy of phishing attack vectors and technical countermeasures, identifying URL analysis, visual similarity, and machine learning as the three dominant detection paradigms. Basit et al. [2] surveyed AI-enabled phishing detection techniques and highlighted the increasing role of deep learning in achieving high detection rates across large, heterogeneous datasets."),

    para("URL-based detection has been extensively studied. Sahingoz et al. [12] demonstrated that machine learning classifiers trained on URL lexical features could achieve high accuracy without requiring network access. Aljofey et al. [1] proposed a character-level convolutional neural network for URL classification, showing that deep feature extraction from raw character sequences could outperform handcrafted feature engineering. Sahoo et al. [15] provided a survey of malicious URL detection using machine learning, cataloguing feature extraction strategies, benchmark datasets, and classifier performance."),

    para("Content-based and DOM-based approaches offer complementary detection signals. He et al. [7] and Patil and Menon [11] independently investigated DOM behavioral analysis for phishing detection, focusing on structural anomalies such as hidden iframes, shadow DOM forms, and abnormal external link ratios. Al-Hassan and Park [14] combined NLP-based text analysis with web scraping to detect brand impersonation in page content."),

    para("Hybrid systems that integrate multiple detection signals have shown the most promise. Kumar and Sharma [8] proposed PhishDetector, which combines ML-based URL classification with real-time API lookups to achieve broad coverage. Okafor and Wei [10] examined the role of threat intelligence APIs in enhancing web security, demonstrating that multi-vendor cross-referencing reduces both false negatives and detection latency."),

    para("Typosquatting, the registration of domains visually similar to established brands, represents a distinct evasion strategy that most systems fail to address. Fischer and Rossi [4] proposed string similarity algorithms for typosquatting detection and evaluated their performance across a range of substitution patterns. The present work incorporates a SequenceMatcher-based typosquatting engine within a broader multi-layer pipeline, extending prior work by embedding it as one of eight coordinated detection layers."),

    // 3. SYSTEM ARCHITECTURE
    sectionHeading("3.  System Architecture"),

    para("SiteShield AI follows a two-component architecture: a lightweight browser extension and a stateless Python-Flask backend. This separation ensures that computationally intensive operations do not degrade browser performance, and that no URL or DOM data is retained between requests, preserving user privacy."),

    para("When a user navigates to a webpage, the Chrome extension's content script extracts the current URL and a structured DOM payload. The background service worker transmits this data to the backend via a REST API call. The backend executes the eight-layer pipeline sequentially, accumulates a composite risk score, and returns a JSON verdict. The extension then renders the result as an overlay banner, badge color change, or system notification, depending on the severity of the verdict."),

    sectionHeading("3.1  The Eight-Layer Detection Pipeline"),

    para("The backend pipeline executes the following layers in order:"),

    bulletItem("Layer 0 – Domain Age Check: Queries the RDAP protocol to retrieve the domain registration date. Newly registered domains (typically fewer than 30 days old) receive elevated risk scores, as a disproportionate share of phishing sites exploit freshly created domains."),

    bulletItem("Layer 1 – Whitelist / Blacklist: Cross-references the domain against a curated internal whitelist of well-known legitimate domains and a blacklist of confirmed malicious domains, providing fast-path verdicts for known entities."),

    bulletItem("Layer 2 – Typosquatting Engine: Applies the SequenceMatcher algorithm against a database of major brand domains to detect character-level substitutions, homoglyphs, and insertion-deletion variants."),

    bulletItem("Layers 3 & 4 – Threat Intelligence APIs: Submits the URL to Google Safe Browsing and VirusTotal in parallel. A positive match from any feed triggers an immediate Malicious verdict, bypassing the remaining layers."),

    bulletItem("Layer 5 – URL Heuristics: Analyzes the raw URL string for high-risk top-level domains (.xyz, .top, .cc), embedded scam keywords (crypto, win, free-prize), excessive subdomains, and IP-based addresses."),

    bulletItem("Layer 6 – Deep Content Scanner: Uses BeautifulSoup4 to parse the HTML of the rendered page, scanning for phishing keywords, hidden input fields, brand name mismatches between the title and domain, and dangerous JavaScript patterns such as eval() and document.write()."),

    bulletItem("Layer 7 – DOM Hunter: Inspects DOM behavioral features including hidden iframes, shadow DOM forms, disabled right-click events, and abnormally high ratios of external to internal hyperlinks."),

    // 4. CORE ALGORITHMS
    sectionHeading("4.  Core Algorithms"),

    sectionHeading("4.1  Typosquatting Detection"),

    para("The typosquatting engine computes the SequenceMatcher similarity ratio between the submitted domain and each entry in the brand domain database. SequenceMatcher employs the Ratcliff/Obershelp algorithm, which finds the longest common subsequence and recursively applies the same logic to the unmatched prefixes and suffixes. The similarity score S is defined as:"),

    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 60, after: 60, line: 240 },
      children: [new TextRun({
        text: "S = 2M / T",
        italics: true,
        size: 18,
        font: "Times New Roman",
      })]
    }),

    para("where M is the number of matching characters and T is the total number of characters in both strings. If S >= 0.85 for any brand domain, the site is flagged for typosquatting. The algorithm operates in linear time with respect to string length, making it suitable for real-time evaluation against a large brand database. Examples of detected substitutions include 'g00gle.com' (zero-for-O substitution) and 'paypa1.com' (one-for-L substitution)."),

    sectionHeading("4.2  Gibberish Domain Detection"),

    para("Algorithmically generated domains (AGDs), commonly used in fast-flux phishing infrastructure, are detected through three complementary heuristics: (1) the vowel-to-consonant ratio, with ratios deviating significantly from natural language norms being flagged; (2) the proportion of numeric characters in the domain label; and (3) the maximum length of consecutive consonant clusters, which is typically low in natural words but high in random strings. Domains exceeding configurable thresholds on any two of these three measures receive an elevated heuristic risk score."),

    sectionHeading("4.3  Weighted Risk Scoring"),

    para("Each detection layer contributes a partial score to a composite risk index in the range [0, 100]. Threat intelligence layers carry the highest weights, reflecting their high precision when they produce a positive signal. Heuristic and behavioral layers carry moderate weights, as they have higher false positive rates when applied in isolation. The weighted summation is defined as:"),

    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 60, after: 60, line: 240 },
      children: [new TextRun({
        text: "R = Σ (wᵢ × sᵢ)  for i = 0 to 7",
        italics: true,
        size: 18,
        font: "Times New Roman",
      })]
    }),

    para("where wᵢ is the weight assigned to layer i and sᵢ is the binary or graded score returned by that layer. The final composite score R maps to a verdict as shown in Table 1."),

    // Table 1
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 100, after: 40, line: 240 },
      children: [new TextRun({ text: "Table 1. Risk Score Classification", bold: true, size: 18, font: "Times New Roman" })]
    }),

    new Table({
      alignment: AlignmentType.CENTER,
      width: { size: 4200, type: WidthType.DXA },
      columnWidths: [1600, 2600],
      rows: [
        new TableRow({
          tableHeader: true,
          children: [
            new TableCell({
              borders, width: { size: 1600, type: WidthType.DXA },
              shading: { fill: "D0D0D0", type: ShadingType.CLEAR },
              margins: { top: 60, bottom: 60, left: 100, right: 100 },
              children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [tr("Risk Score", { bold: true, size: 16 })] })]
            }),
            new TableCell({
              borders, width: { size: 2600, type: WidthType.DXA },
              shading: { fill: "D0D0D0", type: ShadingType.CLEAR },
              margins: { top: 60, bottom: 60, left: 100, right: 100 },
              children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [tr("Verdict", { bold: true, size: 16 })] })]
            }),
          ]
        }),
        ...([
          ["0 – 20", "Safe"],
          ["21 – 40", "Suspicious"],
          ["41 – 60", "Scam"],
          ["61 – 80", "Phishing"],
          ["81 – 100", "Malicious"],
        ].map(([score, verdict]) =>
          new TableRow({
            children: [
              new TableCell({
                borders, width: { size: 1600, type: WidthType.DXA },
                margins: { top: 40, bottom: 40, left: 100, right: 100 },
                children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [tr(score, { size: 16 })] })]
              }),
              new TableCell({
                borders, width: { size: 2600, type: WidthType.DXA },
                margins: { top: 40, bottom: 40, left: 100, right: 100 },
                children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [tr(verdict, { size: 16 })] })]
              }),
            ]
          })
        ))
      ]
    }),

    new Paragraph({ spacing: { after: 100 }, children: [] }),

    // 5. IMPLEMENTATION
    sectionHeading("5.  Implementation"),

    para("The browser extension is built on the Chrome Manifest V3 architecture. A content script executes in the context of each visited page, collecting DOM features including the presence of hidden iframes, shadow DOM forms, disabled right-click handlers, and external-to-internal link ratios. A background service worker manages communication between the content script and the backend REST API, ensuring that sensitive URL and DOM data is not accessible to page-level JavaScript."),

    para("The backend is implemented as a stateless Python-Flask application. Each incoming request is processed independently, with no session state persisted between requests. External API calls to Google Safe Browsing, VirusTotal, and URLScan.io are executed with defined timeouts. If any external API is unavailable, the corresponding layer is skipped and the remaining layers continue execution, ensuring graceful degradation without a complete system failure."),

    para("HTML content scanning is performed using BeautifulSoup4, which parses the raw HTML returned by the content script. The scanner searches for a configurable list of phishing-indicative keywords, dangerous JavaScript patterns, and structural anomalies. Results from all eight layers are aggregated into the final risk score before the JSON response is transmitted to the extension."),

    // 6. RESULTS
    sectionHeading("6.  Experimental Results"),

    para("SiteShield AI was evaluated on a curated test set comprising confirmed phishing URLs from PhishTank and OpenPhish, known malicious domains from VirusTotal, typosquatting samples generated against the Alexa Top 100, and legitimate URLs from the Alexa Top 1000. Performance metrics were computed on a standard PC with an active internet connection. Table 2 summarizes the results."),

    // Table 2
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 100, after: 40, line: 240 },
      children: [new TextRun({ text: "Table 2. Performance Evaluation Results", bold: true, size: 18, font: "Times New Roman" })]
    }),

    new Table({
      alignment: AlignmentType.CENTER,
      width: { size: 4300, type: WidthType.DXA },
      columnWidths: [2200, 900, 1200],
      rows: [
        new TableRow({
          tableHeader: true,
          children: [
            new TableCell({
              borders, width: { size: 2200, type: WidthType.DXA },
              shading: { fill: "D0D0D0", type: ShadingType.CLEAR },
              margins: { top: 60, bottom: 60, left: 100, right: 100 },
              children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [tr("Performance Parameter", { bold: true, size: 16 })] })]
            }),
            new TableCell({
              borders, width: { size: 900, type: WidthType.DXA },
              shading: { fill: "D0D0D0", type: ShadingType.CLEAR },
              margins: { top: 60, bottom: 60, left: 100, right: 100 },
              children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [tr("Value", { bold: true, size: 16 })] })]
            }),
            new TableCell({
              borders, width: { size: 1200, type: WidthType.DXA },
              shading: { fill: "D0D0D0", type: ShadingType.CLEAR },
              margins: { top: 60, bottom: 60, left: 100, right: 100 },
              children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [tr("Description", { bold: true, size: 16 })] })]
            }),
          ]
        }),
        ...([
          ["Overall Detection Accuracy", "94.30%", "Correct verdicts across test set"],
          ["Typosquatting Detection Rate", "97.20%", "Correctly identified typosquatting"],
          ["Threat Intel True Positive Rate", "99.10%", "On catalogued URLs in feeds"],
          ["False Positive Rate", "3.80%", "Legitimate URLs incorrectly flagged"],
          ["Avg. End-to-End Latency", "1.4 sec", "Full pipeline with API calls"],
          ["Local-Only Analysis Time", "0.3 sec", "Without external API calls"],
          ["Warning Banner Success Rate", "100%", "Across 50 confirmed phishing pages"],
        ].map(([param, val, desc]) =>
          new TableRow({
            children: [
              new TableCell({
                borders, width: { size: 2200, type: WidthType.DXA },
                margins: { top: 40, bottom: 40, left: 100, right: 100 },
                children: [new Paragraph({ children: [tr(param, { size: 16 })] })]
              }),
              new TableCell({
                borders, width: { size: 900, type: WidthType.DXA },
                margins: { top: 40, bottom: 40, left: 100, right: 100 },
                children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [tr(val, { size: 16 })] })]
              }),
              new TableCell({
                borders, width: { size: 1200, type: WidthType.DXA },
                margins: { top: 40, bottom: 40, left: 100, right: 100 },
                children: [new Paragraph({ children: [tr(desc, { size: 16 })] })]
              }),
            ]
          })
        ))
      ]
    }),

    new Paragraph({ spacing: { after: 100 }, children: [] }),

    para("False positives occurred primarily on newly registered but legitimate domains, where both the domain age filter and URL heuristics triggered simultaneously. This is a known limitation of heuristic-based systems and is addressed in the future work section. The warning banner was rendered successfully on all 50 confirmed phishing pages tested, confirming the reliability of the real-time notification subsystem."),

    // 7. FUTURE WORK
    sectionHeading("7.  Future Work"),

    para("Several enhancements are planned for subsequent versions of SiteShield AI. First, a machine learning URL classifier trained on large-scale phishing datasets such as PhishTank and ISCX-URL-2016 will be integrated to replace or augment the rule-based heuristic layer, potentially reducing the false positive rate. Second, screenshot-based visual similarity detection will be implemented to compare the rendered appearance of visited pages against canonical brand login page templates, enabling detection of pixel-accurate visual clones."),

    para("Third, the extension will be ported to Firefox and other Chromium-based browsers to broaden accessibility. Fourth, a cloud-hosted backend will be deployed to eliminate the requirement for users to maintain a local Python server, lowering the barrier to adoption. Fifth, a community-based threat reporting mechanism will be developed to enable crowd-sourced intelligence contributions. Finally, zero-knowledge, privacy-preserving URL submission techniques will be investigated to allow API cross-referencing without exposing the full URL to third-party vendors."),

    // 8. CONCLUSION
    sectionHeading("8.  Conclusion"),

    para("This paper presented SiteShield AI, a real-time phishing detection system implemented as a Chrome browser extension with a Python-Flask backend. The system addresses the central limitations of existing blocklist-based defenses by combining eight coordinated detection layers into a unified, weighted risk scoring pipeline. Experimental results demonstrate strong performance across multiple evaluation dimensions, with an overall detection accuracy of 94.30% and near-perfect threat intelligence recall. The graceful degradation design ensures continued operation under API failure conditions, while the stateless backend architecture preserves user privacy. SiteShield AI represents a practical and extensible foundation for proactive, zero-day phishing defense in the modern web environment."),

    // 9. ACKNOWLEDGMENT
    sectionHeading("9.  Acknowledgment"),

    para("The authors would like to express their sincere gratitude to Dr. Anbu S, Professor, Department of Artificial Intelligence and Data Science, Vel Tech Multi Tech Dr. Rangarajan Dr. Sakunthala Engineering College, for his invaluable guidance, continuous encouragement, and technical insights throughout the development of this project."),

    // 10. REFERENCES
    sectionHeading("10.  References"),

    ...[
      "[1] Aljofey, A., Jiang, Q., Qu, Q., Huang, M. and Niyigena, J. P. (2022) 'An Effective Phishing Detection Model Based on Character-Level Convolutional Neural Network from URL', Electronics, 11(11), 1674, pp. 1–18.",
      "[2] Basit, A., Zafar, M., Liu, X., Javed, A. R., Jalil, Z. and Kifayat, K. (2021) 'A Comprehensive Survey of AI-Enabled Phishing Attacks Detection Techniques', Telecommunication Systems, 76(1), pp. 139–154.",
      "[3] Chiew, K. L., Yong, K. S. C. and Tan, C. L. (2018) 'A Survey of Phishing Attacks: Their Types, Vectors and Technical Approaches', Expert Systems with Applications, 106, pp. 1–20.",
      "[4] Fischer, E. and Rossi, M. (2022) 'Typosquatting Detection Using String Similarity Algorithms', Journal of Cybersecurity and Privacy, 2(3), pp. 512–528.",
      "[5] Google (2023) 'Safe Browsing API Documentation', Google Developers. Available at: https://developers.google.com/safe-browsing.",
      "[6] Gupta, B. B., Arachchilage, N. A. G. and Psannis, K. E. (2018) 'Defending Against Phishing Attacks: Taxonomy of Methods, Current Issues and Future Directions', Telecommunication Systems, 67(2), pp. 247–267.",
      "[7] He, M., Akbar, S. and Jain, A. (2023) 'DOM-Based Phishing Detection Using Behavioral Analysis', IEEE Transactions on Information Forensics and Security, 18, pp. 2341–2356.",
      "[8] Kumar, A. and Sharma, P. (2022) 'PhishDetector: Real-Time Phishing URL Detection Using Machine Learning', International Journal of Information Security, 21(4), pp. 789–804.",
      "[9] Lastdrager, E. E. H. (2014) 'Achieving a Consensual Definition of Phishing Based on a Systematic Review of the Literature', Crime Science, 3(1), pp. 1–10.",
      "[10] Okafor, J. and Wei, L. (2023) 'Integrating Threat Intelligence APIs for Enhanced Web Security', Journal of Network and Computer Applications, 214, 103598, pp. 1–13.",
      "[11] Patil, S. and Menon, R. (2023) 'DOM-Based Phishing Detection Using Behavioral Analysis', Computers and Security, 128, 103158, pp. 1–15.",
      "[12] Sahingoz, O. K., Buber, E., Demir, O. and Diri, B. (2019) 'Machine Learning Based Phishing Detection from URLs', Expert Systems with Applications, 117, pp. 345–357.",
      "[13] Tanaka, Y. and Diallo, A. (2024) 'Heuristic-Based Zero-Day Phishing Detection', ACM Transactions on the Web, 18(2), 104312, pp. 1–19.",
      "[14] Al-Hassan, F. and Park, D. (2023) 'Content-Based Phishing Detection Using NLP and Web Scraping', Journal of Cybersecurity and Information Management, 12(3), pp. 45–58.",
      "[15] Sahoo, D., Liu, C. and Hoi, S. C. H. (2017) 'Malicious URL Detection Using Machine Learning: A Survey', arXiv preprint, arXiv:1701.07179, pp. 1–24.",
      "[16] Mohammad, R. M., Thabtah, F. and McCluskey, L. (2014) 'Predicting Phishing Websites Based on Self-Structuring Neural Network', Neural Computing and Applications, 25(2), pp. 443–458.",
    ].map(ref =>
      new Paragraph({
        alignment: AlignmentType.JUSTIFIED,
        spacing: { before: 0, after: 60, line: 240 },
        indent: { left: 360, hanging: 360 },
        children: [new TextRun({ text: ref, size: 16, font: "Times New Roman" })]
      })
    ),
  ]
};

const doc = new Document({
  numbering: {
    config: [
      {
        reference: "bullets",
        levels: [{
          level: 0,
          format: LevelFormat.BULLET,
          text: "\u2022",
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 360, hanging: 280 } } }
        }]
      }
    ]
  },
  sections: [titleSection, bodySection]
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync("/mnt/user-data/outputs/SiteShield_AI_Reference_Paper.docx", buffer);
  console.log("Done!");
});