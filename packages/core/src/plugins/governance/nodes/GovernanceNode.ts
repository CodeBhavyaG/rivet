import { 
  type ChartNode, 
  type PluginNodeImpl, 
  type NodeId, 
  type PortId,
  type EditorDefinition
} from '../../../index.js';
import { newId, dedent, coerceTypeOptional } from '../../../utils/index.js';
import { pluginNodeDefinition } from '../../../model/NodeDefinition.js';
import { PIIDetectionGuardrail, GuardrailEngine } from 'tealtiger';

// =====================
// Governance Node Logic
// =====================

// Mapping from node UI categories to tealtiger PIIDetectionGuardrail detectTypes
const TEALTIGER_TYPES: Partial<Record<GovernanceCategory, string>> = {
  SSN: 'ssn',
  Email: 'email',
  Phone: 'phone',
  CreditCard: 'credit_card',
};

// API keys are not covered by tealtiger's PII guardrail; keep a local deterministic pattern.
const API_KEY_PATTERN = /\b[A-Za-z0-9_-]{20,}\b/g;

type GovernanceCategory = 'SSN' | 'CreditCard' | 'Email' | 'Phone' | 'APIKey';

// Define node data configuration
export type GovernanceNodeData = {
  mode: 'observe' | 'monitor' | 'enforce';
  piiCategories: GovernanceCategory[];
  piiAction: 'detect' | 'redact' | 'block';
  costBudgetUsd: number;
  outputAuthZ: boolean;
};

export type GovernanceNode = ChartNode<'governancePIIScan', GovernanceNodeData>;

// Main node implementation
export const GovernanceNodeImpl: PluginNodeImpl<GovernanceNode> = {
  create() {
    return {
      id: newId<NodeId>(),
      type: 'governancePIIScan',
      data: {
        mode: 'observe',
        piiCategories: [],
        piiAction: 'detect',
        costBudgetUsd: 10,
        outputAuthZ: true,
      },
      title: 'Governance: PII Scan',
      visualData: {
        x: 0,
        y: 0,
        width: 300,
      },
    };
  },

  getUIData() {
    return {
      group: 'Governance',
      contextMenuTitle: 'Governance: PII Scan',
      infoBoxTitle: 'Governance: PII Scan Node',
      infoBoxBody: 'Scans text for PII, enforces cost budgets, and validates output authorization.',
    };
  },

  getInputDefinitions() {
    return [
      {
        id: 'text' as PortId,
        dataType: 'string',
        title: 'Text',
        coerced: true,
        defaultValue: '',
        description: 'The text to evaluate for PII and policy compliance.',
        required: true,
      },
    ];
  },

  getOutputDefinitions() {
    return [
      {
        id: 'output' as PortId,
        dataType: 'string',
        title: 'Output',
        description: 'The original text (if allowed), redacted text (if configured), or empty if blocked.',
      },
      {
        id: 'decision' as PortId,
        dataType: 'object',
        title: 'Decision',
        description: '{action, findings, risk_score, correlation_id, latency_ms}',
      },
      {
        id: 'blocked' as PortId,
        dataType: 'boolean',
        title: 'Blocked',
        description: 'True if the output was blocked by policy.',
      },
    ];
  },

  getEditors(): EditorDefinition<GovernanceNode>[] {
    return [
      {
        type: 'dropdown' as const,
        dataKey: 'mode',
        label: 'Mode',
        options: [
          { value: 'observe', label: 'Observe' },
          { value: 'monitor', label: 'Monitor' },
          { value: 'enforce', label: 'Enforce' },
        ],
        defaultValue: 'observe' as string,
      } as const,
      {
        type: 'stringList' as const,
        dataKey: 'piiCategories',
        placeholder: 'SSN, CreditCard, Email, Phone, APIKey',
        label: 'PII Categories',
      } as const,
      {
        type: 'dropdown' as const,
        dataKey: 'piiAction',
        label: 'PII Action',
        options: [
          { value: 'detect', label: 'Detect Only' },
          { value: 'redact', label: 'Redact' },
          { value: 'block', label: 'Block' },
        ],
        defaultValue: 'detect' as string,
      } as const,
      {
        type: 'number' as const,
        dataKey: 'costBudgetUsd',
        label: 'Cost Budget (USD)',
        defaultValue: 10,
      } as const,
      {
        type: 'toggle' as const,
        dataKey: 'outputAuthZ',
        label: 'Output Authorization',
        useInputToggleDataKey: 'outputAuthZ',
      } as const,
    ];
  },

  getBody(data) {
    return dedent`
      Mode: ${data.mode}
      PII Categories: ${data.piiCategories.join(', ') || 'None'}
      Action: ${data.piiAction}
      Cost Budget: $${data.costBudgetUsd}
      Output Auth: ${data.outputAuthZ}
    `;
  },

  async process(data, inputData) {
    const startTime = Date.now();

    // Get the input text (plain input port, not data-backed, so use coerceTypeOptional)
    const text = coerceTypeOptional(inputData['text' as PortId], 'string') ?? '';

    // Run PII evaluation through tealtiger's PIIDetectionGuardrail (deterministic, no LLM)
    // detect only -> action 'allow' (report detections, never transform/block)
    const guardrailAction = data.piiAction === 'detect' ? 'allow' : data.piiAction;
    const detectTypes = (data.piiCategories ?? [])
      .map((c) => TEALTIGER_TYPES[c])
      .filter((t): t is string => typeof t === 'string');

    const findings: Array<{ type: string; value: string; riskScore: number }> = [];
    let redactedText = text;
    let piiRisk = 0;

    if (detectTypes.length > 0) {
      try {
        const engine = new GuardrailEngine({});
        engine.registerGuardrail(new PIIDetectionGuardrail({
          name: 'governance-pii',
          detectTypes,
          action: guardrailAction as 'allow' | 'redact' | 'block',
          enabled: true,
        }));
        const result = await engine.execute(text);
        const piiResult = result.results?.[0]?.result;
        const detections = piiResult?.metadata?.detections ?? [];
        for (const d of detections) {
          findings.push({ type: d.type, value: d.value, riskScore: piiResult?.riskScore ?? 0 });
        }
        piiRisk = piiResult?.riskScore ?? 0;
        if (guardrailAction === 'redact' && piiResult?.metadata?.redactedText) {
          redactedText = piiResult.metadata.redactedText as string;
        }
      } catch (err) {
        // Fail open: report the error in the decision, never crash the graph
        findings.push({ type: 'tealtiger-error', value: String(err), riskScore: 0 });
      }
    }

    // API key detection stays local (tealtiger does not cover API keys)
    if (data.piiCategories.includes('APIKey')) {
      const matches = text.match(API_KEY_PATTERN);
      if (matches) {
        findings.push({ type: 'APIKey', value: matches[0], riskScore: 90 });
        redactedText = redactedText.replace(API_KEY_PATTERN, '[REDACTED]');
      }
    }

    const latencyMs = Date.now() - startTime;

    let outputValue = text;
    let blockedFlag = false;

    if (data.piiAction === 'redact' && findings.length > 0) {
      outputValue = redactedText;
    }

    if (data.piiAction === 'block' && findings.length > 0) {
      outputValue = '';
      blockedFlag = true;
    }

    // Output authorization: block secrets/unauthorized content (API keys), not general PII
    if (data.outputAuthZ && findings.some(f => f.type === 'APIKey')) {
      outputValue = '';
      blockedFlag = true;
    }

    // Observe mode: never transform or block, only report
    if (data.mode === 'observe') {
      outputValue = text;
      blockedFlag = false;
    }

    const decision: any = {
      action: blockedFlag ? 'DENY' : data.piiAction === 'redact' && findings.length > 0 ? 'REDACT' : 'ALLOW',
      findings,
      risk_score: blockedFlag || findings.length > 0 ? Math.max(piiRisk, 90) : 0,
      mode: data.mode,
      detect_types: detectTypes,
      correlation_id: `gov-${Date.now()}`,
      latency_ms: latencyMs,
    };

    return {
      ['output' as PortId]: {
        type: 'string',
        value: outputValue,
      },
      ['decision' as PortId]: {
        type: 'object',
        value: decision,
      },
      ['blocked' as PortId]: {
        type: 'boolean',
        value: blockedFlag,
      },
    };
  }
};

export const governancePIIScanNode = pluginNodeDefinition(
  GovernanceNodeImpl,
  'Governance: PII Scan'
);
