/* ###
 * IP: GHIDRA
 * NOTE: Phi placement and renaming based on ACM journal articles
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file heritage.hh
/// \brief Utilities for building Static Single Assignment (SSA) form

#ifndef __CPUI_HERITAGE__
#define __CPUI_HERITAGE__

#include "block.hh"

/// Container holding the stack system for the renaming algorithm.  Every disjoint address
/// range (indexed by its initial address) maps to its own Varnode stack.
typedef map<Address, vector<Varnode*>> VariableStack;

/// \brief Label for describing extent of address range that has been heritaged
struct SizePass {
    int4 size; ///< Size of the range (in bytes)
    int4 pass; ///< Pass when the range was heritaged
};

/// \brief Map object for keeping track of which address ranges have been
/// heritaged
///
/// We keep track of a fairly fine grained description of when each address
/// range was entered in SSA form, refered to as \b heritaged or, for Varnode
/// objects, no longer \b free. An address range is added using the add()
/// method, which includes the particular pass when it was entered. The map can
/// be queried using findPass() that informs the caller whether the address has
/// been heritaged and if so in which pass.
class LocationMap {
public:
    /// Iterator into the main map
    typedef map<Address, SizePass>::iterator iterator;

private:
    // Heritaged addresses mapped to range size and pass number
    map<Address, SizePass> themap;
public:
    // Mark new address as \b heritaged
    iterator add (Address addr, int4 size, int4 pass, int4& intersect);
    // Look up if/how given address was heritaged
    iterator find (Address addr);
    // Look up if/how given address was heritaged
    int4 findPass (Address addr) const;
    // Remove a particular entry from the map
    void erase (iterator iter) { themap.erase (iter); }
    // Get starting iterator over heritaged ranges
    iterator begin (void) { return themap.begin (); }
    // Get ending iterator over heritaged ranges
    iterator end (void) { return themap.end (); }
    // Clear the map of heritaged ranges
    void clear (void) { themap.clear (); }
};

/// \brief Priority queue for the phi-node (MULTIEQUAL) placement algorithm
///
/// A \e work-list for basic blocks used during phi-node placement. Implemented
/// as a set of stacks with an associated priority. Blocks are placed in the \e
/// queue with an associated \e priority (or depth) using the insert() method.
/// The current highest priority block is retrieved with the extract() method.
class PriorityQueue {
    // An array of \e stacks, indexed by priority
    vector<vector<FlowBlock*>> queue;
    // The current highest priority index with active blocks
    int4 curdepth;
public:
    PriorityQueue (void) { curdepth = -2; }
    // Reset to an empty queue
    void reset (int4 maxdepth);
    // Insert a block into the queue given its priority
    void insert (FlowBlock* bl, int4 depth);
    // Retrieve the highest priority block
    FlowBlock* extract (void);
    // Return \b true if \b this queue is empty
    bool empty (void) const { return (curdepth == -1); }
};

class Funcdata;
class FuncCallSpecs;

/// \brief Information about heritage passes performed for a specific address
/// space
///
/// For a particular address space, this keeps track of:
///   - how long to delay heritage
///   - how long to delay dead code removal
///   - whether dead code has been removed (for this space)
///   - have warnings been issued
class HeritageInfo {
    friend class Heritage;
    // The address space \b this record describes
    AddrSpace* space;
    // How many passes to delay heritage of this space
    int4 delay;
    // How many passes to delay deadcode removal of this space
    int4 deadcodedelay;
    // >0 if Varnodes in this space have been eliminated
    int4 deadremoved;
    // \b true if the search for LOAD ops to guard has been performed
    bool loadGuardSearch;
    // \b true if warning issued previously
    bool warningissued;
    // Set all fields
    void set (AddrSpace* spc, int4 dl, int4 dcdl)
    {
        space = spc;
        delay = dl;
        deadcodedelay = dcdl;
        deadremoved = 0;
        warningissued = false;
        loadGuardSearch = false;
    }
    // Return \b true if heritage is performed on this space
    bool isHeritaged (void) const { return (space != (AddrSpace*)0); }
    void reset (void)
    {
        deadremoved = 0;
        deadcodedelay = delay;
        warningissued = false;
        loadGuardSearch = false;
    }
};

/// \brief Description of a LOAD operation that needs to be guarded
///
/// Heritage maintains a list of CPUI_LOAD ops that reference the stack
/// dynamically. These can potentially alias stack Varnodes, so we maintain what
/// (possibly limited) information we known about the range of stack addresses
/// that can be referenced.
class LoadGuard {
    friend class Heritage;
    // The LOAD op
    PcodeOp* op;
    // The stack space being loaded from
    AddrSpace* spc;
    // Base offset of the pointer
    uintb pointerBase;
    // Minimum offset of the LOAD
    uintb minimumOffset;
    // Maximum offset of the LOAD
    uintb maximumOffset;
    // Step of any access into this range (0=unknown)
    int4 step;
    // 0 = unanalyzed, 1 = analyzed(partial result), 2 = analyzed(full result)
    int4 analysisState;
    // Convert partial value set analysis into guard range
    void establishRange (const ValueSetRead& valueSet);
    // Convert value set analysis to final guard range
    void finalizeRange (const ValueSetRead& valueSet);

    /// \brief Set a new unanalyzed LOAD guard that initially guards everything
    ///
    /// \param o is the LOAD op
    /// \param s is the (stack) space it is loading from
    /// \param off is the base offset that is indexed from
    void set (PcodeOp* o, AddrSpace* s, uintb off)
    {
        op = o;
        spc = s;
        pointerBase = off;
        minimumOffset = 0;
        maximumOffset = s->getHighest ();
        step = 0;
        analysisState = 0;
    }

public:
    // Get the PcodeOp being guarded
    PcodeOp* getOp (void) const { return op; }
    // Get minimum offset of the guarded range
    uintb getMinimum (void) const { return minimumOffset; }
    // Get maximum offset of the guarded range
    uintb getMaximum (void) const { return maximumOffset; }
    // Get the calculated step associated with the range (or 0)
    int4 getStep (void) const { return step; }
    // Does \b this guard apply to the given address
    bool isGuarded (const Address& addr) const;
    // Return \b true if the range is fully determined
    bool isRangeLocked (void) const { return (analysisState == 2); }
    // Return \b true if the record still describes an active LOAD
    bool isValid (OpCode opc) const
    {
        return (!op->isDead () && op->code () == opc);
    }
};

/// \brief Manage the construction of Static Single Assignment (SSA) form
///
/// With a specific function (Funcdata), this class links the Varnode and
/// PcodeOp objects into the formal data-flow graph structure, SSA form.
/// The full structure can be built over multiple passes. In particular,
/// this allows register data-flow to be analyzed first, and then stack
/// locations can be discovered and promoted to first-class Varnodes in
/// a second pass.
///
/// Varnodes for which it is not known whether they are written to by a
/// PcodeOp are referred to as \b free.  The method heritage() performs
/// a \e single \e pass of constructing SSA form, collecting any \e eligible
/// free Varnodes for the pass and linking them in to the data-flow. A
/// Varnode is considered eligible for a given pass generally based on its
/// address space (see HeritageInfo), which is the main method for delaying
/// linking for stack locations until they are all discovered. In
/// principle a Varnode can be discovered very late and still get linked
/// in on a subsequent pass. Linking causes Varnodes to gain new descendant
/// PcodeOps, which has impact on dead code elimination (see LocationMap).
///
/// The two big aspects of SSA construction are phi-node placement, performed
/// by placeMultiequals(), and the \e renaming algorithm, performed by rename().
/// The various guard* methods are concerned with labeling analyzing
/// data-flow across function calls, STORE, and LOAD operations.
///
/// The phi-node placement algorithm is from (preprint?)
/// "The Static Single Assignment Form and its Computation"
/// by Gianfranco Bilardi and Keshav Pingali, July 22, 1999
///
/// The renaming algorithm taken from
/// "Efficiently computing static single assignment form and the
///  control dependence graph."
/// R. Cytron, J. Ferrante, B. K. Rosen, M. N. Wegman, and F. K. Zadeck
/// ACM Transactions on Programming Languages and Systems,
/// 13(4):451-490, October 1991
class Heritage {
    /// Extra boolean properties on basic blocks for the Augmented Dominator Tree
    enum heritage_flags {
        boundary_node = 1, ///< Augmented Dominator Tree boundary node
        mark_node = 2, ///< Node has already been in queue
        merged_node = 4 ///< Node has already been merged
    };

    /// \brief Node for depth-first traversal of stack references
    struct StackNode {
        enum { nonconstant_index = 1, multiequal = 2 };
        Varnode* vn; ///< Varnode being traversed
        uintb offset; ///< Offset relative to base
        uint4 traversals; ///< What kind of operations has this pointer accumulated
        list<PcodeOp*>::const_iterator iter; ///< Next PcodeOp to follow

        /// \brief Constructor
        /// \param v is the Varnode being visited
        /// \param o is the current offset from the base pointer
        /// \param trav indicates what configurations were seen along the path to this Varnode
        StackNode (Varnode* v, uintb o, uint4 trav)
        {
            vn = v;
            offset = o;
            iter = v->beginDescend ();
            traversals = trav;
        }
    };
    // The function \b this is controlling SSA construction
    Funcdata* fd;
    // Disjoint cover of every heritaged memory location
    LocationMap globaldisjoint;
    // Disjoint cover of memory locations currently being heritaged
    LocationMap disjoint;
    // Parent->child edges in dominator tree
    vector<vector<FlowBlock*>> domchild;
    // Augmented edges
    vector<vector<FlowBlock*>> augment;
    // Block properties for phi-node placement algorithm
    vector<uint4> flags;
    // Dominator depth of individual blocks
    vector<int4> depth;
    // Maximum depth of the dominator tree
    int4 maxdepth;
    // Current pass being executed
    int4 pass;
    // Priority queue for phi-node placement
    PriorityQueue pq;
    // Calculate merge points (blocks containing phi-nodes)
    vector<FlowBlock*> merge;
    // Heritage status for individual address spaces
    vector<HeritageInfo> infolist;
    // List of LOAD operations that need to be guarded
    list<LoadGuard> loadGuard;
    // List of STORE operations taking an indexed pointer to the stack
    list<LoadGuard> storeGuard;
    // List of COPY ops generated by load guards
    vector<PcodeOp*> loadCopyOps;
    // Reset heritage status for all address spaces
    void clearInfoList (void);
    /// \brief Get the heritage status for the given address space
    HeritageInfo* getInfo (AddrSpace* spc)
    {
        return &(infolist[spc->getIndex ()]);
    }
    /// \brief Get the heriage status for the given address space
    const HeritageInfo* getInfo (AddrSpace* spc) const
    {
        return &(infolist[spc->getIndex ()]);
    }

    void splitJoinLevel (vector<Varnode*>& lastcombo, vector<Varnode*>& nextlev,
                         JoinRecord* joinrec);
    void splitJoinRead (Varnode* vn, JoinRecord* joinrec);
    void splitJoinWrite (Varnode* vn, JoinRecord* joinrec);
    void floatExtensionRead (Varnode* vn, JoinRecord* joinrec);
    void floatExtensionWrite (Varnode* vn, JoinRecord* joinrec);
    void processJoins (void);
    // Build the augmented dominator tree
    void buildADT (void);

    int4 collect (Address addr, int4 size, vector<Varnode*>& read,
                  vector<Varnode*>& write, vector<Varnode*>& input) const;

    bool callOpIndirectEffect (const Address& addr, int4 size, PcodeOp* op) const;
    Varnode* normalizeReadSize (Varnode* vn, const Address& addr, int4 size);
    Varnode* normalizeWriteSize (Varnode* vn, const Address& addr, int4 size);
    Varnode* concatPieces (const vector<Varnode*>& vnlist, PcodeOp* insertop,
                           Varnode* finalvn);

    void splitPieces (const vector<Varnode*>& vnlist, PcodeOp* insertop,
                      const Address& addr, int4 size, Varnode* startvn);

    void findAddressForces (vector<PcodeOp*>& copySinks, vector<PcodeOp*>& forces);
    void propagateCopyAway (PcodeOp* op);
    void handleNewLoadCopies (void);
    void analyzeNewLoadGuards (void);
    void generateLoadGuard (StackNode& node, PcodeOp* op, AddrSpace* spc);
    void generateStoreGuard (StackNode& node, PcodeOp* op, AddrSpace* spc);
    bool protectFreeStores (AddrSpace* spc, vector<PcodeOp*>& freeStores);
    bool discoverIndexedStackPointers (AddrSpace* spc, vector<PcodeOp*>& freeStores,
                                       bool checkFreeStores);
    void reprocessFreeStores (AddrSpace* spc, vector<PcodeOp*>& freeStores);

    void guard (const Address& addr, int4 size, vector<Varnode*>& read,
                vector<Varnode*>& write, vector<Varnode*>& inputvars);

    void guardInput (const Address& addr, int4 size, vector<Varnode*>& input);
    void guardCallOverlappingInput (FuncCallSpecs* fc, const Address& addr,
                                    int4 size);
    void guardCalls (uint4 flags, const Address& addr, int4 size,
                     vector<Varnode*>& write);
    void guardStores (const Address& addr, int4 size, vector<Varnode*>& write);
    void guardLoads (uint4 flags, const Address& addr, int4 size,
                     vector<Varnode*>& write);
    void guardReturns (uint4 flags, const Address& addr, int4 size,
                       vector<Varnode*>& write);

    static void buildRefinement (vector<int4>& refine, const Address& addr,
                                 int4 size, const vector<Varnode*>& vnlist);

    void splitByRefinement (Varnode* vn, const Address& addr,
                            const vector<int4>& refine,
                            vector<Varnode*>& split);
    void refineRead (Varnode* vn, const Address& addr,
                     const vector<int4>& refine, vector<Varnode*>& newvn);
    void refineWrite (Varnode* vn, const Address& addr,
                      const vector<int4>& refine, vector<Varnode*>& newvn);
    void refineInput (Varnode* vn, const Address& addr, const vector<int4>& refine,
                      vector<Varnode*>& newvn);
    void remove13Refinement (vector<int4>& refine);

    bool refinement (const Address& addr, int4 size,
                     const vector<Varnode*>& readvars,
                     const vector<Varnode*>& writevars,
                     const vector<Varnode*>& inputvars);

    void visitIncr (FlowBlock* qnode, FlowBlock* vnode);
    void calcMultiequals (const vector<Varnode*>& write);
    void renameRecurse (BlockBasic* bl, VariableStack& varstack);
    void bumpDeadcodeDelay (Varnode* vn);
    void placeMultiequals (void);
    void rename (void);

public:
    Heritage (Funcdata* data); ///< Constructor

    /// \brief Get the pass number when the given address was heritaged
    ///
    /// \param addr is the given address
    /// \return the pass number or -1 if the address has not been heritaged
    int4 heritagePass (const Address& addr) const
    {
        return globaldisjoint.findPass (addr);
    }
    int4 numHeritagePasses (AddrSpace* spc) const;
    // Inform system of dead code removal in given space
    void seenDeadCode (AddrSpace* spc);
    // Get pass delay for heritaging the given space
    int4 getDeadCodeDelay (AddrSpace* spc) const;
    // Set delay for a specific space
    void setDeadCodeDelay (AddrSpace* spc, int4 delay);
    // Return \b true if it is \e safe to remove dead code
    bool deadRemovalAllowed (AddrSpace* spc) const;
    bool deadRemovalAllowedSeen (AddrSpace* spc);
    // Initialize information for each space
    void buildInfoList (void);
    // Force regeneration of basic block structures
    void forceRestructure (void) { maxdepth = -1; }
    // Reset all analysis of heritage
    void clear (void);
    ///< Perform one pass of heritage
    void heritage (void);
    // Get list of LOAD ops that are guarded
    const list<LoadGuard>& getLoadGuards (void) const { return loadGuard; }
    // Get list of STORE ops that are guarded
    const list<LoadGuard>& getStoreGuards (void) const { return storeGuard; }
    // Get LoadGuard record associated with given PcodeOp
    const LoadGuard* getStoreGuard (PcodeOp* op) const;
};

#endif
