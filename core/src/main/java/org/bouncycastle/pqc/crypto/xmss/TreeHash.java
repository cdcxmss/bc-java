package org.bouncycastle.pqc.crypto.xmss;

import java.util.ArrayDeque;
import java.util.Stack;

/**
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class TreeHash {
	
	private ArrayDeque<XMSSNode> sharedStack;
	
	private XMSSNode storedNode;
	
	private int height;
	
	private final int initHeight;
	
	private XMSS xmss;
	
	private byte[] seed;
	
	private boolean initialized = false;
	
	/**
     * Creates a new TreeHash.
     *
     * @param sharedStack Stack
     * @param height Height
     * @param xmss the xmss instance
     */
    public TreeHash(ArrayDeque<XMSSNode> sharedStack, int height, XMSS xmss) {
    	this.sharedStack = sharedStack;
    	this.initHeight = height;
    	this.xmss = xmss;
    }
	
	/**
     * Updates the TreeHash. This means it executes Algorithm 1 Treehash from BDS paper once.
     *
     * @param startIndex
     * @param otsHashAddress
     */
    public void update(int startIndex,  OTSHashAddress otsHashAddress){
    	OTSHashAddress oAddress = new OTSHashAddress();
		oAddress.setLayerAddress(otsHashAddress.getLayerAddress());
		oAddress.setTreeAddress(otsHashAddress.getTreeAddress());
		LTreeAddress lTreeAddress = new LTreeAddress();
		lTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
		lTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		hashTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
		hashTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
		Stack<XMSSNode> stack = new Stack<XMSSNode>();
		otsHashAddress.setOTSAddress(startIndex);
		lTreeAddress.setLTreeAddress(startIndex);
		xmss.wotsPlus.importKeys(xmss.getWOTSPlusSecretKey(startIndex), xmss.publicSeed);
			
		XMSSNode node = xmss.lTree(xmss.wotsPlus.getPublicKey(otsHashAddress), xmss.publicSeed, lTreeAddress);
		while(!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()) {
			node = xmss.randomizeHash(stack.pop(), node, xmss.publicSeed, hashTreeAddress);
			hashTreeAddress.setTreeHeight(hashTreeAddress.getTreeHeight() + 1);
			hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
			node.setHeight(node.getHeight() + 1);
		}
		stack.push(node);
		if(node.getHeight() == this.height){
			this.storedNode = node;
		}
		else {
			this.sharedStack.push(node);
		}
    }
    
    /**
     * initialize the TreeHash with the given seed and set the height.
     * @param seed
     */
    public void initialize(byte[] seed){
    	this.seed = seed;
    	height = initHeight;
    	initialized = true;
    }

	public ArrayDeque<XMSSNode> getSharedStack() {
		return sharedStack;
	}

	public void setSharedStack(ArrayDeque<XMSSNode> sharedStack) {
		this.sharedStack = sharedStack;
	}

	public XMSSNode getNode() {
		return storedNode;
	}

	public void setNode(XMSSNode node) {
		this.storedNode = node;
	}

	public byte[] getSeed() {
		return seed;
	}

	public boolean isInitialized() {
		return initialized;
	}

	public int getHeight() {
		return height;
	}

	public void setHeight(int height) {
		this.height = height;
	}

}
