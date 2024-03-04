import { generateRandomG1Element, generateRandomG2Element } from 'crypto-wasm-new';
import { runFrostKeygen, stringToBytes } from './utils';
import { ParticipantG1, ParticipantG2 } from '../src/frost-dkg';
import { PublicKeyBase } from '../src/types';
import { initializeWasm } from '../src';

describe('Frost DKG', () => {
  let pkBaseG1: PublicKeyBase;
  let pkBaseG2: PublicKeyBase;

  beforeAll(async () => {
    await initializeWasm();
    pkBaseG1 = new PublicKeyBase(generateRandomG1Element());
    pkBaseG2 = new PublicKeyBase(generateRandomG2Element());
  });

  it('run in G1', () => {
    const threshold = 3;
    const total = 5;
    const protocolId = stringToBytes('test DKG in G1');
    const participants: ParticipantG1[] = [];
    for (let i = 1; i <= total; i++) {
      participants.push(new ParticipantG1(i, threshold, total, protocolId))
    }
    runFrostKeygen(participants, pkBaseG1)
  })

  it('run in G2', () => {
    const threshold = 3;
    const total = 5;
    const protocolId = stringToBytes('test DKG in G2');
    const participants: ParticipantG2[] = [];
    for (let i = 1; i <= total; i++) {
      participants.push(new ParticipantG2(i, threshold, total, protocolId));
    }
    runFrostKeygen(participants, pkBaseG2)
  })
});