import {
  initializeWasm,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBSCredential,
  BBSCredentialBuilder,
  BBSKeypair,
  BBSPlusCredential,
  BBSPlusCredentialBuilder,
  BBSPlusKeypairG2,
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BBSPlusSignatureParamsG1,
  BBSPublicKey,
  BBSSecretKey,
  BBSSignatureParams,
  CredentialSchema,
  DefaultSchemaParsingOpts,
  InequalityProtocol,
  META_SCHEMA_STR,
  PresentationBuilder,
  PS_SIGNATURE_PARAMS_LABEL_BYTES,
  PSCredential,
  PSCredentialBuilder,
  PSKeypair,
  PSPublicKey,
  PSSecretKey,
  PSSignatureParams, SignatureType, BDDT16Credential, BDDT16_MAC_PARAMS_LABEL_BYTES, BDDT16CredentialBuilder
} from '../../src';
import { checkResult, stringToBytes } from '../utils';
import { checkPresentationJson, getExampleSchema } from './utils';
import { PederCommKey } from '../../src/ped-com';
import { BDDT16MacParams, BDDT16MacSecretKey } from '../../src/bddt16-mac';
import { isKvac } from '../scheme';

describe.each([true, false])(
  `Presentation creation and verification with withSchemaRef=%s involving credentials with different signature schemes`,
  (withSchemaRef) => {
    let skBbs: BBSSecretKey, pkBbs: BBSPublicKey;
    let skBbsPlus: BBSPlusSecretKey, pkBbsPlus: BBSPlusPublicKeyG2;
    let skPs: PSSecretKey, pkPs: PSPublicKey;
    let skBddt16: BDDT16MacSecretKey;

    let credentialBbs: BBSCredential;
    let credentialBbsPlus: BBSPlusCredential;
    let credentialPs: PSCredential;
    let credentialBddt16: BDDT16Credential;

    const nonEmbeddedSchema = {
      $id: 'https://example.com?hash=abc123ff',
      [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
      type: 'object'
    };

    beforeAll(async () => {
      await initializeWasm();
      const paramsBbs = BBSSignatureParams.generate(1, BBS_SIGNATURE_PARAMS_LABEL_BYTES);
      const paramsBbsPlus = BBSPlusSignatureParamsG1.generate(1, BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES);
      const paramsPs = PSSignatureParams.generate(100, PS_SIGNATURE_PARAMS_LABEL_BYTES);
      const keypairBbs = BBSKeypair.generate(paramsBbs, stringToBytes('seed1'));
      const keypairBbsPlus = BBSPlusKeypairG2.generate(paramsBbsPlus, stringToBytes('seed2'));
      const keypairPs = PSKeypair.generate(paramsPs, stringToBytes('seed3'));
      skBddt16 = BDDT16MacSecretKey.generate(stringToBytes('seed4'));
      skBbs = keypairBbs.sk;
      pkBbs = keypairBbs.pk;
      skBbsPlus = keypairBbsPlus.sk;
      pkBbsPlus = keypairBbsPlus.pk;
      skPs = keypairPs.sk;
      pkPs = keypairPs.pk;

      for (const [credBuilder, sk, pk] of [
        [BBSCredentialBuilder, skBbs, pkBbs],
        [BBSPlusCredentialBuilder, skBbsPlus, pkBbsPlus],
        [PSCredentialBuilder, skPs, pkPs],
        [BDDT16CredentialBuilder, skBddt16, undefined]
      ]) {
        const schema = getExampleSchema(11);
        // @ts-ignore
        const builder = new credBuilder();
        if (withSchemaRef) {
          builder.schema = new CredentialSchema(nonEmbeddedSchema, DefaultSchemaParsingOpts, true, undefined, schema);
        } else {
          builder.schema = new CredentialSchema(schema);
        }
        builder.subject = {
          fname: 'John',
          lname: 'Smith',
          isbool: true,
          sensitive: {
            secret: 'my-secret-that-wont-tell-anyone',
            email: 'john.smith@example.com',
            SSN: '123-456789-0',
            userId: 'user:123-xyz-#'
          },
          location: {
            country: 'USA',
            city: 'New York'
          },
          timeOfBirth: 1662010849619,
          physical: {
            height: 181.5,
            weight: 210,
            BMI: 23.25
          },
          score: -13.5
        };
        const credential = builder.sign(sk);
        if (!(sk instanceof BDDT16MacSecretKey)) {
          checkResult(credential.verify(pk));
        } else {
          checkResult(credential.verifyUsingSecretKey(sk));
        }
        if (sk instanceof BBSSecretKey) {
          credentialBbs = credential;
        }
        if (sk instanceof BBSPlusSecretKey) {
          credentialBbsPlus = credential;
        }
        if (sk instanceof PSSecretKey) {
          credentialPs = credential;
        }
        if (sk instanceof BDDT16MacSecretKey) {
          credentialBddt16 = credential;
        }
      }
    });

    it('works', () => {
      const commKeyId = 'commKeyId';
      const commKey = new PederCommKey(stringToBytes('test'));

      const builder = new PresentationBuilder();
      expect(builder.addCredential(credentialBbs, pkBbs)).toEqual(0);
      expect(builder.addCredential(credentialBbsPlus, pkBbsPlus)).toEqual(1);
      expect(builder.addCredential(credentialPs, pkPs)).toEqual(2);
      expect(builder.addCredential(credentialBddt16)).toEqual(3);

      builder.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));
      builder.markAttributesRevealed(1, new Set<string>(['credentialSubject.isbool']));
      builder.markAttributesRevealed(2, new Set<string>(['credentialSubject.location.city']));
      builder.markAttributesRevealed(3, new Set<string>(['credentialSubject.location.country']));

      builder.markAttributesEqual(
        [0, 'credentialSubject.sensitive.SSN'],
        [1, 'credentialSubject.sensitive.SSN'],
        [2, 'credentialSubject.sensitive.SSN'],
        [3, 'credentialSubject.sensitive.SSN']
      );
      builder.markAttributesEqual(
        [0, 'credentialSubject.sensitive.email'],
        [1, 'credentialSubject.sensitive.email'],
        [2, 'credentialSubject.sensitive.email'],
        [3, 'credentialSubject.sensitive.email']
      );

      const inEqualEmail = 'alice@example.com';
      builder.enforceAttributeInequality(0, 'credentialSubject.sensitive.email', inEqualEmail, commKeyId, commKey);
      builder.enforceAttributeInequality(1, 'credentialSubject.sensitive.email', inEqualEmail, commKeyId);
      builder.enforceAttributeInequality(2, 'credentialSubject.sensitive.email', inEqualEmail, commKeyId);
      builder.enforceAttributeInequality(3, 'credentialSubject.sensitive.email', inEqualEmail, commKeyId);

      const pres = builder.finalize();

      expect(pres.spec.credentials.length).toEqual(4);

      expect(pres.spec.credentials[0].sigType).toEqual(SignatureType.Bbs);
      expect(pres.spec.credentials[1].sigType).toEqual(SignatureType.BbsPlus);
      expect(pres.spec.credentials[2].sigType).toEqual(SignatureType.Ps);
      expect(pres.spec.credentials[3].sigType).toEqual(SignatureType.Bddt16);

      expect(pres.spec.credentials[0].revealedAttributes).toEqual({
        credentialSubject: {
          fname: 'John',
          lname: 'Smith'
        }
      });
      expect(pres.spec.credentials[1].revealedAttributes).toEqual({
        credentialSubject: {
          isbool: true
        }
      });
      expect(pres.spec.credentials[2].revealedAttributes).toEqual({
        credentialSubject: {
          location: { city: 'New York' }
        }
      });
      expect(pres.spec.credentials[3].revealedAttributes).toEqual({
        credentialSubject: {
          location: { country: 'USA' }
        }
      });

      for (let i = 0; i < 4; i++) {
        expect(pres.spec.credentials[i].attributeInequalities).toEqual({
          credentialSubject: {
            sensitive: {
              email: [{ inEqualTo: inEqualEmail, paramId: commKeyId, protocol: InequalityProtocol.Uprove }]
            }
          }
        });
      }

      const pp = new Map();
      pp.set(commKeyId, commKey);

      const pks = new Map();
      pks.set(0, pkBbs);
      pks.set(1, pkBbsPlus);
      pks.set(2, pkPs);
      checkResult(pres.verify(pks, undefined, pp));
      checkPresentationJson(pres, pks, undefined, pp);

      pks.set(3, skBddt16);
      checkResult(pres.verify(pks, undefined, pp));
      checkPresentationJson(pres, pks, undefined, pp);
    });
  }
);
