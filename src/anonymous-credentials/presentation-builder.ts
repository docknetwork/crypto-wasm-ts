import { Versioned } from './versioned';
import { Credential } from './credential';
import { BBSPlusPublicKeyG2, SignatureG1, SignatureParamsG1 } from '../bbs-plus';
import {
  CompositeProofG1,
  MetaStatements,
  QuasiProofSpecG1,
  Statement,
  Statements,
  Witness,
  Witnesses
} from '../composite-proof';
import { LegoProvingKey, LegoProvingKeyUncompressed } from '../legosnark';
import { CredentialSchema } from './schema';
import { getRevealedAndUnrevealed } from '../sign-verify-js-objs';

type AttributeRef = [number, string];
type AttributeEquality = AttributeRef[];

export class PresentationBuilder extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.0.1';

  _context?: Uint8Array;
  _nonce?: Uint8Array;
  proof?: CompositeProofG1;
  // Just for debugging
  _proofSpec?: QuasiProofSpecG1;
  spec: PresentationSpec;

  credentials: [Credential, BBSPlusPublicKeyG2][];
  revealedAttributes: Map<number, Set<string>>;
  attributeEqualities: AttributeEquality[];

  constructor() {
    super(PresentationBuilder.VERSION);
    this.credentials = [];
    this.revealedAttributes = new Map();
    this.attributeEqualities = [];
    this.spec = new PresentationSpec();
  }

  addCredential(credential: Credential, pk: BBSPlusPublicKeyG2): number {
    this.credentials.push([credential, pk]);
    return this.credentials.length - 1;
  }

  markAttributesRevealed(credIdx: number, attributeNames: Set<string>) {
    if (credIdx >= this.credentials.length) {
      throw new Error(`Invalid credential index ${credIdx}. Number of credentials is ${this.credentials.length}`);
    }
    let revealed = this.revealedAttributes.get(credIdx);
    if (revealed === undefined) {
      revealed = new Set<string>;
    }
    this.revealedAttributes.set(credIdx, new Set(...revealed, ...attributeNames));
  }

  markAttributesEqual(equality: AttributeEquality) {
    // TODO:
  }

  markStatusRegMember(credIdx: number, attributeName: string) {
    // TODO:
  }

  enforceBounds(credIdx: number, attributeName: string, min: number, max: number, provingKey: LegoProvingKey | LegoProvingKeyUncompressed) {
    // TODO:
  }

  verifiablyEncrypt(credIdx: number, attributeName: string, ) {
    // TODO:
  }

  finalize() {
    // TODO:
    const numCreds = this.credentials.length;
    let maxAttribs = 2; // version and schema
    let sigParams = SignatureParamsG1.generate(maxAttribs, Credential.getLabelBytes());

    const statements = new Statements();
    const metaStatements = new MetaStatements();
    const witnesses = new Witnesses();

    for (let i = 0; i < numCreds; i++) {
      const cred = this.credentials[i][0];
      const schema = (cred.schema as CredentialSchema).schema;
      const flattenedSchema = CredentialSchema.flattenSchema(schema);
      const numAttribs = flattenedSchema[0].length;
      if (maxAttribs < numAttribs) {
        sigParams.adapt(numAttribs);
        maxAttribs = numAttribs;
      }
      let revealedNames = this.revealedAttributes.get(i);
      if (revealedNames === undefined) {
        revealedNames = new Set();
      }
      // TODO: Make cred-status, schema and version as revealed
      const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
        cred.serializeForSigning(),
        revealedNames,
        (cred.schema as CredentialSchema).encoder
      );
      const statement = Statement.bbsSignature(sigParams.adapt(numAttribs), this.credentials[i][1], revealedMsgs, false);
      const witness = Witness.bbsSignature(cred.signature as SignatureG1, unrevealedMsgs, false);
      statements.add(statement);
      witnesses.add(witness);
    }

    // TODO: Include version and spec in context
    this._proofSpec = new QuasiProofSpecG1(statements, metaStatements, [], this._context);
    this.proof = CompositeProofG1.generateUsingQuasiProofSpec(this._proofSpec, witnesses, this._nonce);
  }

  get context(): Uint8Array | undefined {
    return this._context;
  }

  set context(context: Uint8Array | undefined) {
    this._context = context;
  }

  get nonce(): Uint8Array | undefined {
    return this._nonce;
  }

  set nonce(nonce: Uint8Array | undefined) {
    this._nonce = nonce;
  }

  toJSON(): string {
    // TODO:
    return JSON.stringify({
      $version: this.version
    });
  }
}

/**
 * Specifies what the presentation is proving like what credentials, whats being revealed, which attributes are being proven
 * equal, bounds being enforced, etc
 */
class PresentationSpec {
  constructor() {
  }
}
