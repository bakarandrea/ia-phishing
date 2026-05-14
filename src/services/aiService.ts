import { GoogleGenAI, Type } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

export interface ScanResult {
  riskLevel: 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
  score: number; // 0-100
  classification: string;
  explanation: string;
  threats: string[];
  recommendation: string;
}

const scanSchema = {
  type: Type.OBJECT,
  properties: {
    riskLevel: {
      type: Type.STRING,
      description: "SAFE, SUSPICIOUS, or PHISHING",
      enum: ["SAFE", "SUSPICIOUS", "PHISHING"]
    },
    score: {
      type: Type.NUMBER,
      description: "Probability score of phishing (0-100)"
    },
    classification: {
      type: Type.STRING,
      description: "One word classification like Legitimate or Phishing"
    },
    explanation: {
      type: Type.STRING,
      description: "Detailed explanation of why it was flagged or why it's safe"
    },
    threats: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: "List of specific threats found (e.g., urgency, fake sender, malicious link)"
    },
    recommendation: {
      type: Type.STRING,
      description: "What the user should do next"
    }
  },
  required: ["riskLevel", "score", "classification", "explanation", "threats", "recommendation"]
};

export async function scanContent(content: string, type: 'email' | 'url'): Promise<ScanResult> {
  const prompt = `Analyze the following ${type} for phishing indicators. 
  Look for suspicious patterns, urgent language, fake domains, and deceptive techniques.
  
  ${type.toUpperCase()} CONTENT:
  ${content}
  `;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: prompt,
      config: {
        systemInstruction: "You are an expert cybersecurity analyst specialized in phishing detection. Grade the content with high precision.",
        responseMimeType: "application/json",
        responseSchema: scanSchema,
      },
    });

    return JSON.parse(response.text) as ScanResult;
  } catch (error) {
    console.error("Scan error:", error);
    throw error;
  }
}

export async function scanFile(fileData: { mimeType: string, data: string, fileName: string }): Promise<ScanResult> {
  const prompt = `Analyze the attached file "${fileData.fileName}" for malicious intent, 
  phishing content, or suspicious scripts/links.
  
  If it's a PDF or text file, read the content. 
  Determine if this is a phishing attempt.
  `;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: {
        parts: [
          { inlineData: { mimeType: fileData.mimeType, data: fileData.data } },
          { text: prompt }
        ]
      },
      config: {
        systemInstruction: "You are an expert cybersecurity analyst. Analyze the attachment for phishing or malware potential.",
        responseMimeType: "application/json",
        responseSchema: scanSchema,
      },
    });

    return JSON.parse(response.text) as ScanResult;
  } catch (error) {
    console.error("File scan error:", error);
    throw error;
  }
}
