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
     * Updates the TreeHash.
     *
     * @param node Node
     */
    public void update(XMSSNode node, XMSSAddress address) {
		node = new XMSSNode(0, node.getValue());
		while (!sharedStack.isEmpty() && sharedStack.getLast().getHeight() == node.getHeight()) {
		    node = xmss.randomizeHash(sharedStack.pop(), node, xmss.getPublicSeed(), address);
		}
	
		if (storedNode == null) {
		    storedNode = node;
		} else {
		    if (storedNode.getHeight() == node.getHeight()) {
		    	storedNode = xmss.randomizeHash(storedNode, node, xmss.getPublicSeed(), address);
		    } else {
		    	sharedStack.push(node);
		    }
		}
	
		if (storedNode.getHeight() == initHeight) {
		    height = Integer.MAX_VALUE;
		} else {
		    height = node.getHeight();
		}
    }
    
    public XMSSNode update(int startIndex, int targetNodeHeight, OTSHashAddress otsHashAddress, LTreeAddress lTreeAddress, HashTreeAddress hashTreeAddress){
    	if (startIndex % (1 << targetNodeHeight) != 0) {
			throw new IllegalArgumentException("leaf at index startIndex needs to be a leftmost one");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		if (lTreeAddress == null) {
			throw new NullPointerException("lTreeAddress == null");
		}
		if (hashTreeAddress == null) {
			throw new NullPointerException("hashTreeAddress == null");
		}
		Stack<XMSSNode> stack = new Stack<XMSSNode>();
		for (int i = 0; i < (1 << targetNodeHeight); i++) {
			xmss.wotsPlus.importKeys(xmss.getWOTSPlusSecretKey(startIndex + i), xmss.publicSeed);
			otsHashAddress.setOTSAddress(startIndex + i);
			lTreeAddress.setLTreeAddress(startIndex + i);
			XMSSNode node = xmss.lTree(xmss.wotsPlus.getPublicKey(otsHashAddress), xmss.publicSeed, lTreeAddress);
			hashTreeAddress.setTreeHeight(0);
			hashTreeAddress.setTreeIndex(startIndex + i);
			while(!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()) {
				hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
				node = xmss.randomizeHash(stack.pop(), node, xmss.publicSeed, hashTreeAddress);
				node.setHeight(node.getHeight() + 1);
				hashTreeAddress.setTreeHeight(hashTreeAddress.getTreeHeight() + 1);
			}
			stack.push(node);
		}
		return stack.pop();
    }
    
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
